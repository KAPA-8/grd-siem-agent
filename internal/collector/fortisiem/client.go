package fortisiem

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
	incidentPath = "/phoenix/rest/pub/incident"
	tokenPath    = "/phoenix/rest/pub/security/oauth/token"

	requestTimeout    = 60 * time.Second
	maxResponseBytes  = 50 << 20
	maxErrorBodyBytes = 4 << 10
	maxErrorBodyShown = 300

	defaultMaxRetries   = 3
	defaultRetryBase    = time.Second
	defaultMaxRetryWait = 2 * time.Minute
)

// APIError is a non-2xx answer from the FortiSIEM API.
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
	Hint       string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("fortisiem %s %s: HTTP %d", e.Method, e.Path, e.StatusCode)
	if e.Hint != "" {
		msg += ": " + e.Hint
	}
	if e.Body != "" {
		msg += " (" + e.Body + ")"
	}
	return msg
}

// errNotJSON reports a 2xx answer whose body is not JSON (an HTML login or
// error page, typically: a wrong URL or a proxy in between).
var errNotJSON = errors.New("la respuesta no es JSON")

// Client is a minimal FortiSIEM REST client. Requests are sequential;
// 429/502/503/504 are retried with exponential backoff honouring Retry-After,
// and with OAuth a 401 refreshes the token and retries once.
type Client struct {
	baseURL      string
	httpClient   *http.Client
	auth         authenticator
	tlsHint      string
	secrets      []string // redacted from error bodies
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
	for _, secret := range []string{s.password, s.clientSecret} {
		if len(secret) >= 4 {
			c.secrets = append(c.secrets, secret)
		}
	}
	if s.deployment == deploymentOnPrem {
		c.tlsHint = "si el Supervisor usa un certificado autofirmado, configura siem.credentials.ca_cert_file con su PEM (preferido) o validate_ssl: false"
	} else {
		c.tlsHint = "FortiSIEM Cloud siempre verifica el certificado: revisa el almacén de CAs del sistema, o ca_cert_file si hay un proxy con inspección TLS"
	}
	if s.authMode == authModeOAuth {
		c.auth = newOAuthTokenSource(c, s.clientID, s.clientSecret, now)
	} else {
		c.auth = newBasicAuth(s.organization, s.username, s.password)
	}
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
			Msg("fortisiem: retrying request")
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

// transportError describes a failed request without its query string (the
// OAuth GET fallback carries the client secret there).
func (c *Client) transportError(ctx context.Context, req *http.Request, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if siemhttp.IsCertificateError(err) {
		msg := fmt.Sprintf("fortisiem: falló la verificación del certificado TLS de %s: %v", req.URL.Host, unwrapURLError(err))
		if fp := siemhttp.CertificateFingerprint(err); fp != "" {
			msg += fmt.Sprintf(" (huella SHA-256 del certificado recibido: %s; compárala con la del Supervisor antes de confiar en él)", fp)
		}
		return errors.New(msg + "; " + c.tlsHint)
	}
	return fmt.Errorf("fortisiem: %s %s%s: %w (comprueba la conectividad del agente con el puerto 443/TCP del Supervisor o de FortiSIEM Cloud)", req.Method, req.URL.Host, req.URL.Path, unwrapURLError(err))
}

// unwrapURLError drops *url.Error's copy of the full request URL.
func unwrapURLError(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return urlErr.Err
	}
	return err
}

// redact removes the configured secrets from text taken from a response.
func (c *Client) redact(text string) string {
	for _, secret := range c.secrets {
		text = strings.ReplaceAll(text, secret, "***")
	}
	return text
}

// readBody closes resp.Body and returns it, or an *APIError for non-2xx.
func (c *Client) readBody(resp *http.Response, method, path, hint string) ([]byte, error) {
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: c.errorBody(resp, body), Hint: hint}
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fortisiem: leyendo la respuesta de %s: %w", path, err)
	}
	if len(data) > maxResponseBytes {
		return nil, fmt.Errorf("fortisiem: la respuesta de %s supera %d bytes", path, maxResponseBytes)
	}
	return data, nil
}

// errorBody is a short, redacted excerpt of an error answer. HTML pages are
// summarized by their content type instead of being shown.
func (c *Client) errorBody(resp *http.Response, body []byte) string {
	if looksLikeMarkup(body) {
		return "respuesta HTML/XML, Content-Type " + orUnknown(resp.Header.Get("Content-Type"))
	}
	text := strings.Join(strings.Fields(string(body)), " ")
	if len(text) > maxErrorBodyShown {
		text = truncateRunes(text, maxErrorBodyShown) + "..."
	}
	return c.redact(text)
}

func looksLikeMarkup(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	return len(trimmed) > 0 && trimmed[0] == '<'
}

func orUnknown(s string) string {
	if s == "" {
		return "(ninguno)"
	}
	return s
}

// decodeJSON decodes a JSON document (numbers as json.Number) into any.
func decodeJSON(data []byte) (any, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return nil, errNotJSON
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("%w: %v", errNotJSON, err)
	}
	return v, nil
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

// truncateRunes cuts s to at most n characters without splitting a UTF-8 sequence.
func truncateRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}

// --- incidents -----------------------------------------------------------------

// incidentPage is one answer of POST /phoenix/rest/pub/incident. FortiSIEM
// Cloud sends {start, total, pages, sizePerPage, data, queryId}; 7.4 may omit
// pages/sizePerPage/queryId and send total as a string. Items that are not
// objects are counted in Invalid.
type incidentPage struct {
	Total    int64
	HasTotal bool
	Data     []map[string]any
	Invalid  int
	Items    int // len(data), objects or not
}

// queryIncidents runs one page of the incident query.
func (c *Client) queryIncidents(ctx context.Context, q incidentQuery) (*incidentPage, error) {
	body, err := json.Marshal(q)
	if err != nil {
		return nil, err
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
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+incidentPath, bytes.NewReader(body))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Authorization", header)
			return req, nil
		})
		if err != nil {
			return nil, err
		}
		if resp.StatusCode == http.StatusUnauthorized && !reauthenticated && c.auth.refreshable() {
			// Revoked or expired token: refresh once and retry once.
			drainAndClose(resp.Body)
			c.auth.invalidate(ctx, authz)
			reauthenticated = true
			continue
		}
		data, err := c.readBody(resp, http.MethodPost, incidentPath, incidentHint(resp.StatusCode, c.auth.mode()))
		if err != nil {
			return nil, err
		}
		page, err := parseIncidentPage(data)
		if err != nil {
			return nil, fmt.Errorf("fortisiem: respuesta inesperada de %s (HTTP %d, Content-Type %s): %w; comprueba que siem.api_url es la URL del Supervisor o de FortiSIEM Cloud",
				incidentPath, resp.StatusCode, orUnknown(resp.Header.Get("Content-Type")), err)
		}
		return page, nil
	}
}

// incidentHint turns common failures of the incident query into an
// actionable message.
func incidentHint(status int, authMode string) string {
	switch {
	case status == http.StatusUnauthorized && authMode == authModeBasic:
		return "FortiSIEM rechazó el usuario o la contraseña. El usuario debe llevar el prefijo de su organización: " +
			"Enterprise → super/<usuario>; Service Provider → <Org>/<usuario> (o super/<usuario> con tenant_id). " +
			"Revisa siem.credentials.organization, username y password (o GRD_SIEM_PASSWORD)"
	case status == http.StatusUnauthorized:
		return "FortiSIEM rechazó el token OAuth; revisa siem.credentials.client_id y client_secret (o GRD_SIEM_CLIENT_SECRET) y los permisos del cliente API"
	case status == http.StatusForbidden:
		return "el usuario no tiene permiso para consultar incidentes por la API REST; asígnale un rol con acceso a Incidents"
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed:
		return "no existe " + incidentPath + " en esta URL; revisa siem.api_url (la URL del Supervisor o de FortiSIEM Cloud, sin /phoenix)"
	case status == http.StatusBadRequest:
		return "FortiSIEM rechazó la consulta de incidentes"
	}
	return ""
}

// parseIncidentPage accepts the documented envelope (an object with data)
// and, defensively, a bare array of incidents.
func parseIncidentPage(body []byte) (*incidentPage, error) {
	v, err := decodeJSON(body)
	if err != nil {
		return nil, err
	}
	page := &incidentPage{}
	var items []any
	switch doc := v.(type) {
	case []any:
		items = doc
	case map[string]any:
		data, present := doc["data"]
		if !present || data == nil {
			if msg := errorMessage(doc); msg != "" {
				return nil, fmt.Errorf("FortiSIEM devolvió un error: %s", msg)
			}
		} else if list, ok := data.([]any); ok {
			items = list
		} else {
			return nil, fmt.Errorf("el campo data no es una lista")
		}
		if total, ok := intCode(doc["total"]); ok {
			page.Total, page.HasTotal = total, true
		}
	default:
		return nil, errNotJSON
	}
	page.Items = len(items)
	for _, item := range items {
		if inc, ok := item.(map[string]any); ok {
			page.Data = append(page.Data, inc)
		} else {
			page.Invalid++
		}
	}
	return page, nil
}

// errorMessage extracts an error text from an envelope without data.
func errorMessage(doc map[string]any) string {
	for _, key := range []string{"error", "errorMessage", "message"} {
		switch v := doc[key].(type) {
		case string:
			if s := strings.TrimSpace(v); s != "" {
				return truncateRunes(s, maxErrorBodyShown)
			}
		case map[string]any:
			if s := errorMessage(v); s != "" {
				return s
			}
		}
	}
	return ""
}
