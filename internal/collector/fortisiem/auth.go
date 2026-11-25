package fortisiem

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	authModeBasic = "basic"
	authModeOAuth = "oauth"

	defaultOrganization = "super"

	// defaultTokenTTL applies when the token response has no usable
	// expires_in (FortiSIEM Cloud answers 86400).
	defaultTokenTTL = time.Hour
	// tokenRefreshMargin refreshes the token this long before it expires.
	tokenRefreshMargin = 60 * time.Second
)

// noOAuthMessage is the answer to a FortiSIEM without the token endpoint
// (OAuth arrived in 7.5.0; on-prem 7.4.x only has user and password).
const noOAuthMessage = "esta versión de FortiSIEM no tiene tokens OAuth (requiere 7.5+): usa usuario y contraseña " +
	"(siem.credentials.auth_mode: basic con organization, username y password)"

// authenticator produces the Authorization header of the API calls.
type authenticator interface {
	header(ctx context.Context) (string, error)
	// refreshable reports whether a 401 is worth one retry with a new credential.
	refreshable() bool
	// invalidate drops the credential the server rejected (authz) after a 401.
	invalidate(ctx context.Context, authz string)
	mode() string
}

// basicAuth sends Basic base64("<organization>/<username>:<password>") on
// every call. The password may contain ':' (only the first one separates the
// user from the password) and any other character.
type basicAuth struct {
	value string
}

func newBasicAuth(organization, username, password string) *basicAuth {
	return &basicAuth{value: "Basic " + base64.StdEncoding.EncodeToString([]byte(basicUser(organization, username)+":"+password))}
}

// basicUser is "<organization>/<username>"; a username that already carries
// an organization prefix ("super/admin") is used as-is.
func basicUser(organization, username string) string {
	if strings.Contains(username, "/") {
		return username
	}
	if organization == "" {
		organization = defaultOrganization
	}
	return organization + "/" + username
}

func (b *basicAuth) header(context.Context) (string, error) { return b.value, nil }
func (b *basicAuth) refreshable() bool                      { return false }
func (b *basicAuth) invalidate(context.Context, string)     {}
func (b *basicAuth) mode() string                           { return authModeBasic }

// oauthTokenSource exchanges the client credentials for a bearer token
// (FortiSIEM 7.5+), caches it until expires_in - 60 s and refreshes it.
//
// The token is requested with POST application/x-www-form-urlencoded; only
// when that answers 404/405 is GET with the same query parameters tried.
// Any answer that is not JSON (FortiSIEM answers an HTML error page to the
// GET) is reported as a FortiSIEM without OAuth, never parsed.
type oauthTokenSource struct {
	client       *Client
	clientID     string
	clientSecret string
	now          func() time.Time

	// sem guards the fields below and serializes refreshes; a channel lets a
	// waiter give up when its context is cancelled.
	sem       chan struct{}
	token     string
	refreshAt time.Time
}

func newOAuthTokenSource(client *Client, clientID, clientSecret string, now func() time.Time) *oauthTokenSource {
	return &oauthTokenSource{
		client:       client,
		clientID:     clientID,
		clientSecret: clientSecret,
		now:          now,
		sem:          make(chan struct{}, 1),
	}
}

func (t *oauthTokenSource) mode() string      { return authModeOAuth }
func (t *oauthTokenSource) refreshable() bool { return true }

func (t *oauthTokenSource) lock(ctx context.Context) error {
	select {
	case t.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *oauthTokenSource) unlock() { <-t.sem }

func (t *oauthTokenSource) header(ctx context.Context) (string, error) {
	if err := t.lock(ctx); err != nil {
		return "", err
	}
	defer t.unlock()
	if t.token != "" && t.now().Before(t.refreshAt) {
		return "Bearer " + t.token, nil
	}
	return t.exchangeLocked(ctx)
}

func (t *oauthTokenSource) invalidate(ctx context.Context, authz string) {
	if err := t.lock(ctx); err != nil {
		return
	}
	defer t.unlock()
	if t.token != "" && authz == "Bearer "+t.token {
		t.token = ""
	}
}

func (t *oauthTokenSource) form() url.Values {
	return url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {t.clientID},
		"client_secret": {t.clientSecret},
	}
}

func (t *oauthTokenSource) exchangeLocked(ctx context.Context) (string, error) {
	post := func() (*http.Response, error) {
		return t.client.roundTrip(ctx, func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.client.baseURL+tokenPath, strings.NewReader(t.form().Encode()))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Accept", "application/json")
			return req, nil
		})
	}
	resp, err := post()
	if err != nil {
		return "", err
	}
	// FortiSIEM Cloud sometimes answers 400 "Invalid input parameters" to a valid request
	// right after issuing another token (seen on a real tenant): retry briefly.
	for retry := 0; retry < tokenTransientRetries; retry++ {
		var transient bool
		resp, transient = peekTransientTokenRejection(resp)
		if !transient {
			break
		}
		drainAndClose(resp.Body)
		log.Warn().Int("attempt", retry+1).Msg("fortisiem: transient 400 from the OAuth token endpoint; retrying")
		if err := t.client.sleep(ctx, tokenTransientDelay*time.Duration(retry+1)); err != nil {
			return "", err
		}
		if resp, err = post(); err != nil {
			return "", err
		}
	}
	method := http.MethodPost
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
		drainAndClose(resp.Body)
		log.Warn().Int("status", resp.StatusCode).Msg("fortisiem: POST to the OAuth token endpoint not accepted; trying GET")
		method = http.MethodGet
		resp, err = t.client.roundTrip(ctx, func() (*http.Request, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.client.baseURL+tokenPath+"?"+t.form().Encode(), nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Accept", "application/json")
			return req, nil
		})
		if err != nil {
			return "", err
		}
		if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed {
			drainAndClose(resp.Body)
			return "", fmt.Errorf("fortisiem: el endpoint de token OAuth %s no existe (HTTP %d): %s", tokenPath, resp.StatusCode, noOAuthMessage)
		}
	}

	status, contentType := resp.StatusCode, resp.Header.Get("Content-Type")
	data, err := t.client.readBody(resp, method, tokenPath, tokenHint(resp.StatusCode))
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && strings.HasPrefix(apiErr.Body, "respuesta HTML/XML") && tokenHint(status) == "" {
			return "", fmt.Errorf("fortisiem: el endpoint de token no devolvió JSON (HTTP %d, Content-Type %s): %s; si es FortiSIEM 7.5+, revisa siem.api_url",
				status, orUnknown(contentType), noOAuthMessage)
		}
		return "", err
	}
	v, err := decodeJSON(data)
	doc, isObject := v.(map[string]any)
	if err != nil || !isObject {
		return "", fmt.Errorf("fortisiem: el endpoint de token no devolvió JSON (HTTP %d, Content-Type %s): %s; si es FortiSIEM 7.5+, revisa siem.api_url",
			status, orUnknown(contentType), noOAuthMessage)
	}
	token := nonEmpty(doc["access_token"])
	if token == "" {
		return "", fmt.Errorf("fortisiem: la respuesta del endpoint de token no tiene access_token")
	}
	ttl := defaultTokenTTL
	if secs, ok := number(doc["expires_in"]); ok && secs > 0 {
		ttl = time.Duration(secs * float64(time.Second))
	}
	margin := tokenRefreshMargin
	if ttl <= 2*margin {
		margin = ttl / 2
	}
	t.token = token
	t.refreshAt = t.now().Add(ttl - margin)
	log.Debug().Dur("expires_in", ttl).Msg("fortisiem: OAuth token obtained")
	return "Bearer " + t.token, nil
}

// Transient 400 "Invalid input parameters" retries on the OAuth token endpoint.
const (
	tokenTransientRetries = 2
	tokenTransientDelay   = 1500 * time.Millisecond
)

// peekTransientTokenRejection reports whether resp is the transient 400 "Invalid input
// parameters"; the body stays readable for the caller.
func peekTransientTokenRejection(resp *http.Response) (*http.Response, bool) {
	if resp.StatusCode != http.StatusBadRequest {
		return resp, false
	}
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(buf))
	return resp, strings.Contains(strings.ToLower(string(buf)), "invalid input parameters")
}

// tokenHint explains a refused token request.
func tokenHint(status int) string {
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return "FortiSIEM rechazó las credenciales OAuth; revisa siem.credentials.client_id y client_secret (o GRD_SIEM_CLIENT_SECRET)"
	}
	return ""
}
