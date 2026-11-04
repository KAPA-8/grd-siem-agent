package stellarcyber

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/grd-platform/grd-siem-agent/internal/siemhttp"
)

const (
	tokenPath      = "/connect/api/v1/access_token"
	searchPath     = "/connect/api/data/aella-ser-*/_search"
	casesPath      = "/connect/api/v1/cases"
	casesHealthAPI = "/connect/api/v1/cases/health"

	requestTimeout    = 30 * time.Second
	maxResponseBytes  = 50 << 20
	maxErrorBodyBytes = 4 << 10
	maxErrorBodyShown = 512

	defaultMaxRetries   = 3
	defaultRetryBase    = time.Second
	defaultMaxRetryWait = 2 * time.Minute
)

// APIError is a non-2xx answer from the Stellar Cyber API.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("stellar cyber %s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	if hint := statusHint(e.Path, e.StatusCode); hint != "" {
		msg += ": " + hint
	}
	if e.Body != "" {
		msg += " (" + e.Body + ")"
	}
	return msg
}

// statusHint turns common failures into an actionable message.
func statusHint(path string, status int) string {
	switch {
	case path == tokenPath && status == http.StatusUnauthorized:
		return "invalid credentials; check siem.credentials.api_key and, with auth_mode api_token, the username (the account email, case-sensitive)"
	case path == tokenPath && status == http.StatusForbidden:
		return "the account may not use the API; API access needs a local (non-SSO) account, and All-Access tokens need root scope"
	case path == tokenPath && (status == http.StatusNotFound || status == http.StatusMethodNotAllowed):
		return "token endpoint not found; check siem.api_url"
	case status == http.StatusUnauthorized:
		return "the access token was rejected"
	case path == searchPath && status == http.StatusForbidden:
		return "this key cannot read the alert index; use siem.data_source: cases, or a root All-Access api_token (scoped keys need Stellar Cyber 6.3+)"
	case strings.HasPrefix(path, casesPath) && status == http.StatusForbidden:
		return "this key lacks permission to read cases"
	}
	return ""
}

// Client is a minimal Stellar Cyber REST client. Requests are sequential;
// 429/502/503/504 are retried with exponential backoff honouring Retry-After,
// and a 401 on a data call refreshes the token and retries once.
type Client struct {
	baseURL      string
	httpClient   *http.Client
	auth         *tokenSource
	tlsHint      string
	maxRetries   int
	retryBase    time.Duration
	maxRetryWait time.Duration
	sleep        func(ctx context.Context, d time.Duration) error
	now          func() time.Time
}

func newClient(baseURL string, httpClient *http.Client, s settings, now func() time.Time) *Client {
	c := &Client{
		baseURL:      baseURL,
		httpClient:   httpClient,
		maxRetries:   defaultMaxRetries,
		retryBase:    defaultRetryBase,
		maxRetryWait: defaultMaxRetryWait,
		sleep:        sleepContext,
		now:          now,
	}
	if s.deployment == deploymentOnPrem {
		c.tlsHint = "for a self-signed certificate set siem.credentials.ca_cert_file (preferred) or validate_ssl: false"
	} else {
		c.tlsHint = "Stellar Cyber SaaS certificates are always verified; check the system CA store, or set ca_cert_file for a TLS-inspecting proxy"
	}
	allowLegacy := s.deployment == deploymentOnPrem && s.authMode == authModeAPIToken
	c.auth = newTokenSource(c, s.authMode, s.username, s.apiKey, allowLegacy, now)
	return c
}

// roundTrip sends the request built by newReq, retrying 429, 502, 503 and
// 504 up to maxRetries times. The caller must close the response body.
func (c *Client) roundTrip(ctx context.Context, newReq func() (*http.Request, error)) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		req, err := newReq()
		if err != nil {
			return nil, err
		}
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, c.transportError(ctx, req, err)
		}
		if !isRetryableStatus(resp.StatusCode) || attempt >= c.maxRetries {
			return resp, nil
		}
		wait := c.retryDelay(attempt, resp.Header.Get("Retry-After"))
		drainAndClose(resp.Body)
		log.Warn().
			Int("status", resp.StatusCode).
			Str("path", req.URL.Path).
			Dur("wait", wait).
			Int("attempt", attempt+1).
			Msg("stellar cyber: retrying request")
		if err := c.sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

func isRetryableStatus(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryDelay honours Retry-After (seconds or HTTP date, capped) and otherwise
// backs off exponentially: retryBase, 2x, 4x...
func (c *Client) retryDelay(attempt int, retryAfter string) time.Duration {
	if retryAfter = strings.TrimSpace(retryAfter); retryAfter != "" {
		var wait time.Duration
		parsed := false
		if secs, err := strconv.Atoi(retryAfter); err == nil && secs >= 0 {
			wait, parsed = time.Duration(secs)*time.Second, true
		} else if at, err := http.ParseTime(retryAfter); err == nil {
			wait, parsed = at.Sub(c.now()), true
		}
		if parsed {
			return min(max(wait, 0), c.maxRetryWait)
		}
	}
	return min(c.retryBase<<attempt, c.maxRetryWait)
}

func (c *Client) transportError(ctx context.Context, req *http.Request, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if siemhttp.IsCertificateError(err) {
		return fmt.Errorf("stellar cyber: TLS certificate verification failed for %s: %w (%s)", req.URL.Host, err, c.tlsHint)
	}
	return fmt.Errorf("stellar cyber: %s %s%s: %w", req.Method, req.URL.Host, req.URL.Path, unwrapURLError(err))
}

// unwrapURLError drops *url.Error's copy of the full request URL.
func unwrapURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// getJSON performs an authenticated GET and decodes the JSON answer into out.
func (c *Client) getJSON(ctx context.Context, path string, query url.Values, out any) error {
	target := c.baseURL + path
	if len(query) > 0 {
		target += "?" + encodeQuery(query)
	}

	reauthenticated := false
	for {
		var authz string
		resp, err := c.roundTrip(ctx, func() (*http.Request, error) {
			header, err := c.auth.header(ctx)
			if err != nil {
				return nil, err
			}
			authz = header
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/json")
			// The /connect/api/data passthrough answers 406 "Content-Type header [] is
			// not supported" to a GET without it, even with no body (seen on SaaS).
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", header)
			return req, nil
		})
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusUnauthorized && !reauthenticated {
			// Revoked or expired token: refresh once and retry once.
			drainAndClose(resp.Body)
			c.auth.invalidate(ctx, authz)
			reauthenticated = true
			continue
		}
		return decodeResponse(resp, http.MethodGet, path, out)
	}
}

// decodeResponse closes resp.Body, turns non-2xx answers into *APIError and
// decodes JSON bodies (numbers as json.Number) up to maxResponseBytes.
func decodeResponse(resp *http.Response, method, path string, out any) error {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		text := strings.TrimSpace(string(body))
		if len(text) > maxErrorBodyShown {
			text = text[:maxErrorBodyShown] + "..."
		}
		return &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: text}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return fmt.Errorf("stellar cyber: reading %s response: %w", path, err)
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("stellar cyber: %s response exceeds %d bytes", path, maxResponseBytes)
	}
	if out == nil {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("stellar cyber: decoding %s response: %w", path, err)
	}
	return nil
}

func drainAndClose(body io.ReadCloser) {
	_, _ = io.Copy(io.Discard, io.LimitReader(body, maxErrorBodyBytes))
	body.Close()
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// --- API calls -------------------------------------------------------------

type searchResponse struct {
	Hits struct {
		Total totalHits `json:"total"`
		Hits  []Hit     `json:"hits"`
	} `json:"hits"`
}

// totalHits accepts both {"value": N, "relation": ...} and a bare N.
type totalHits struct{ Value int64 }

func (t *totalHits) UnmarshalJSON(b []byte) error {
	var n json.Number
	if err := json.Unmarshal(b, &n); err == nil {
		t.Value, _ = n.Int64()
		return nil
	}
	var obj struct {
		Value json.Number `json:"value"`
	}
	if err := json.Unmarshal(b, &obj); err == nil {
		t.Value, _ = obj.Value.Int64()
	}
	return nil
}

// searchAlerts runs a URI search on the alert index, sorted by write_time.
func (c *Client) searchAlerts(ctx context.Context, q string, from, size int) (*searchResponse, error) {
	query := url.Values{}
	query.Set("q", q)
	query.Set("size", strconv.Itoa(size))
	query.Set("from", strconv.Itoa(from))
	query.Set("sort", fieldWriteTime+":asc")
	query.Set("track_total_hits", "true")
	var out searchResponse
	if err := c.getJSON(ctx, searchPath, query, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// probeAlerts checks read access to the alert index with an empty query.
func (c *Client) probeAlerts(ctx context.Context) error {
	query := url.Values{}
	query.Set("q", probeAlertsQuery)
	query.Set("size", "0")
	return c.getJSON(ctx, searchPath, query, &searchResponse{})
}

type stellarCase struct {
	ID         string      `json:"_id"`
	Name       string      `json:"name"`
	Status     string      `json:"status"`
	ModifiedAt epochMillis `json:"modified_at"`
}

// epochMillis decodes an epoch-milliseconds number (or digit string).
type epochMillis struct {
	ms int64
	ok bool
}

func (e *epochMillis) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	e.ms, e.ok = epochMs(v)
	return nil
}

type casesResponse struct {
	Data struct {
		Cases []stellarCase `json:"cases"`
		Total json.Number   `json:"total"`
	} `json:"data"`
}

func (r *casesResponse) total() int64 {
	n, err := r.Data.Total.Int64()
	if err != nil {
		return 0
	}
	return n
}

func (c *Client) listCases(ctx context.Context, query url.Values) (*casesResponse, error) {
	var out casesResponse
	if err := c.getJSON(ctx, casesPath, query, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type caseAlertsResponse struct {
	Data struct {
		Docs []Hit `json:"docs"`
	} `json:"data"`
}

func (c *Client) caseAlerts(ctx context.Context, caseID string, skip, limit int) ([]Hit, error) {
	query := url.Values{}
	query.Set("skip", strconv.Itoa(skip))
	query.Set("limit", strconv.Itoa(limit))
	var out caseAlertsResponse
	if err := c.getJSON(ctx, casesPath+"/"+url.PathEscape(caseID)+"/alerts", query, &out); err != nil {
		return nil, err
	}
	return out.Data.Docs, nil
}

type healthResponse struct {
	Data struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	} `json:"data"`
}

// health calls GET /cases/health (5.2+), which always answers 200.
func (c *Client) health(ctx context.Context) (*healthResponse, error) {
	var out healthResponse
	if err := c.getJSON(ctx, casesHealthAPI, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
