package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/models"
	"github.com/grd-platform/grd-siem-agent/internal/version"
)

const sendTimeout = 30 * time.Second

// API paths matching the platform's route structure.
const (
	pathRegister  = "/api/v1/siem-agent/register"
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
func NewSender(platformCfg config.PlatformConfig) *Sender {
	return &Sender{
		platformURL: platformCfg.URL,
		agentToken:  platformCfg.AgentToken,
		httpClient: &http.Client{
			Timeout: sendTimeout,
		},
	}
}

// Register registers a new agent with the platform using the org API key.
// Returns the agent_id and agent_token.
func Register(ctx context.Context, platformURL, orgAPIKey string, req models.RegisterRequest) (*models.RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling register request: %w", err)
	}

	url := platformURL + pathRegister
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+orgAPIKey)

	client := &http.Client{Timeout: sendTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("registration request: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("registration failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var result models.RegisterResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decoding register response: %w", err)
	}

	return &result, nil
}

// FetchRemoteConfig gets the agent's configuration from the platform.
func (s *Sender) FetchRemoteConfig(ctx context.Context) (*models.RemoteConfig, error) {
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

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetch config failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var cfg models.RemoteConfig
	if err := json.Unmarshal(respBody, &cfg); err != nil {
		return nil, fmt.Errorf("decoding remote config: %w", err)
	}

	return &cfg, nil
}

// SendSync sends a batch of alerts to the platform.
func (s *Sender) SendSync(ctx context.Context, payload models.SyncPayload) (*models.SyncResponse, error) {
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

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("sync failed (%d): %s", resp.StatusCode, string(respBody))
	}

	var result models.SyncResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decoding sync response: %w", err)
	}

	log.Debug().
		Int("alerts_imported", result.AlertsImported).
		Int("alerts_skipped", result.AlertsSkipped).
		Bool("limit_reached", result.LimitReached).
		Msg("sync response received")

	return &result, nil
}

// SendHeartbeat sends a heartbeat to the platform.
func (s *Sender) SendHeartbeat(ctx context.Context, hb models.HeartbeatPayload) error {
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

	if resp.StatusCode >= 400 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("heartbeat failed (%d): %s", resp.StatusCode, string(respBody))
	}

	log.Debug().Int("status", resp.StatusCode).Msg("heartbeat sent")
	return nil
}

// setAuthHeaders adds the agent authentication headers.
func (s *Sender) setAuthHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+s.agentToken)
	req.Header.Set("X-Agent-Version", version.Version)
}
