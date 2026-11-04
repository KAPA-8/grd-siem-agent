package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/models"
	"github.com/grd-platform/grd-siem-agent/internal/version"
)

const (
	// sendTimeout bounds heartbeat and config requests.
	sendTimeout = 30 * time.Second
	// syncTimeout is longer than the platform's 60s maxDuration for the sync
	// route, so the agent waits for the real outcome instead of retrying a
	// request the server is still processing.
	syncTimeout = 90 * time.Second
	// maxResponseBytes bounds every platform response the agent reads.
	maxResponseBytes = 1 << 20
	// maxErrorBodyBytes bounds the error body kept in error messages.
	maxErrorBodyBytes = 2 << 10
)

// API paths matching the platform's route structure.
const (
	pathConfig    = "/api/v1/siem-agent/config"
	pathHeartbeat = "/api/v1/siem-agent/heartbeat"
	pathSync      = "/api/v1/siem-agent/sync"
)

// Sender sends data to the cloud platform via HTTPS.
type Sender struct {
	platformURL string
	agentToken  string
	httpClient  *http.Client
}

// NewSender creates a new platform sender using the agent token.
// Timeouts are applied per request (see sendTimeout and syncTimeout).
func NewSender(platformCfg config.PlatformConfig) *Sender {
	return &Sender{
		platformURL: strings.TrimRight(platformCfg.URL, "/"),
		agentToken:  platformCfg.AgentToken,
		httpClient:  &http.Client{},
	}
}

// readBody reads a bounded response body.
func readBody(resp *http.Response) ([]byte, error) {
	return io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
}

// httpError builds an *HTTPError with a bounded body.
func httpError(op string, status int, body []byte) error {
	text := strings.TrimSpace(string(body))
	if len(text) > maxErrorBodyBytes {
		text = text[:maxErrorBodyBytes] + "..."
	}
	return &HTTPError{Op: op, StatusCode: status, Body: text}
}

// FetchRemoteConfig gets the agent's configuration from the platform.
func (s *Sender) FetchRemoteConfig(ctx context.Context) (*models.RemoteConfig, error) {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()

	url := s.platformURL + pathConfig
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	s.setAuthHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching remote config: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := readBody(resp)

	if resp.StatusCode >= 400 {
		return nil, httpError("fetch config", resp.StatusCode, respBody)
	}

	var cfg models.RemoteConfig
	if err := json.Unmarshal(respBody, &cfg); err != nil {
		return nil, fmt.Errorf("decoding remote config: %w", err)
	}

	return &cfg, nil
}

// SendSync sends a batch of alerts to the platform. A non-2xx answer is
// returned as *HTTPError (see IsPermanent).
func (s *Sender) SendSync(ctx context.Context, payload models.SyncPayload) (*models.SyncResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, syncTimeout)
	defer cancel()

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshaling sync payload: %w", err)
	}

	url := s.platformURL + pathSync
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	s.setAuthHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending sync: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := readBody(resp)
	if err != nil {
		return nil, fmt.Errorf("reading sync response: %w", err)
	}

	if resp.StatusCode >= 300 {
		return nil, httpError("sync", resp.StatusCode, respBody)
	}

	var result models.SyncResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decoding sync response: %w", err)
	}

	log.Debug().
		Bool("success", result.Success).
		Int("alerts_imported", result.AlertsImported).
		Int("alerts_duplicate", result.AlertsDuplicate).
		Int("alerts_skipped", result.AlertsSkipped).
		Int("alerts_errors", result.AlertsErrors).
		Int("alerts_rejected", result.AlertsRejected).
		Bool("limit_reached", result.LimitReached).
		Msg("sync response received")

	return &result, nil
}

// SendHeartbeat sends a heartbeat to the platform.
func (s *Sender) SendHeartbeat(ctx context.Context, hb models.HeartbeatPayload) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()

	body, err := json.Marshal(hb)
	if err != nil {
		return fmt.Errorf("marshaling heartbeat: %w", err)
	}

	url := s.platformURL + pathHeartbeat
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	s.setAuthHeaders(req)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending heartbeat: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := readBody(resp)
	if resp.StatusCode >= 300 {
		return httpError("heartbeat", resp.StatusCode, respBody)
	}

	log.Debug().Int("status", resp.StatusCode).Msg("heartbeat sent")
	return nil
}

// setAuthHeaders adds the agent authentication headers.
func (s *Sender) setAuthHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+s.agentToken)
	req.Header.Set("X-Agent-Version", version.Version)
}
