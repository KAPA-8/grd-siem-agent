package stellarcyber

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	authModeAPIToken  = "api_token"
	authModeScopedKey = "scoped_key"

	// defaultTokenTTL applies when the token response has no usable "exp"
	// (Stellar Cyber JWTs live 10 minutes by default).
	defaultTokenTTL = 10 * time.Minute
	// tokenRefreshMargin refreshes the JWT this long before it expires.
	tokenRefreshMargin = 60 * time.Second
)

// tokenResponse is the body of POST /connect/api/v1/access_token. "exp" is
// the absolute expiry in epoch seconds. There is no "expiration_utc" field.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	Exp         any    `json:"exp"`
}

// tokenSource exchanges the configured credential for a short-lived JWT,
// caches it and refreshes it before it expires.
//
//   - api_token (All-Access): Basic base64(email:token) + form content type.
//   - scoped_key (5.5+): Bearer <key>.
//
// Legacy on-prem builds (pre-5.x) have no token endpoint: when it answers
// 404/405 and legacy is allowed (on-prem + api_token), every call is sent
// with the Basic header instead. SaaS never does that.
type tokenSource struct {
	client      *Client
	authMode    string
	username    string
	apiKey      string
	allowLegacy bool
	now         func() time.Time

	// sem guards the fields below and serializes refreshes, so concurrent
	// callers share one token exchange. A channel instead of a mutex lets a
	// waiter give up when its context is cancelled.
	sem       chan struct{}
	token     string
	refreshAt time.Time
	legacy    bool
}

func newTokenSource(client *Client, authMode, username, apiKey string, allowLegacy bool, now func() time.Time) *tokenSource {
	return &tokenSource{
		client:      client,
		authMode:    authMode,
		username:    username,
		apiKey:      apiKey,
		allowLegacy: allowLegacy,
		now:         now,
		sem:         make(chan struct{}, 1),
	}
}

func (t *tokenSource) lock(ctx context.Context) error {
	select {
	case t.sem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *tokenSource) unlock() { <-t.sem }

// header returns the Authorization header value for a data call, exchanging
// the credential for a new JWT when there is none or it is about to expire.
func (t *tokenSource) header(ctx context.Context) (string, error) {
	if err := t.lock(ctx); err != nil {
		return "", err
	}
	defer t.unlock()

	if t.legacy {
		return t.basic(), nil
	}
	if t.token != "" && t.now().Before(t.refreshAt) {
		return "Bearer " + t.token, nil
	}
	return t.exchangeLocked(ctx)
}

// invalidate drops the cached credential after the server rejected a call
// made with authz (a 401), so the next header() exchanges again. A token
// that was already replaced by a concurrent refresh is left alone.
func (t *tokenSource) invalidate(ctx context.Context, authz string) {
	if err := t.lock(ctx); err != nil {
		return
	}
	defer t.unlock()

	switch {
	case t.legacy && authz == t.basic():
		t.legacy = false // probe the token endpoint again
	case t.token != "" && authz == "Bearer "+t.token:
		t.token = ""
	}
}

func (t *tokenSource) basic() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(t.username+":"+t.apiKey))
}

func (t *tokenSource) exchangeLocked(ctx context.Context) (string, error) {
	resp, err := t.client.roundTrip(ctx, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.client.baseURL+tokenPath, http.NoBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		if t.authMode == authModeScopedKey {
			req.Header.Set("Authorization", "Bearer "+t.apiKey)
		} else {
			req.Header.Set("Authorization", t.basic())
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		return req, nil
	})
	if err != nil {
		return "", err
	}

	if t.allowLegacy && (resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed) {
		drainAndClose(resp.Body)
		log.Warn().
			Int("status", resp.StatusCode).
			Msg("stellar cyber: no access_token endpoint (pre-5.x on-prem); using Basic authentication on every call")
		t.legacy = true
		t.token = ""
		return t.basic(), nil
	}

	var body tokenResponse
	if err := decodeResponse(resp, http.MethodPost, tokenPath, &body); err != nil {
		return "", err
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("stellar cyber: token response has no access_token")
	}

	now := t.now()
	expiry := now.Add(defaultTokenTTL)
	if exp, ok := numeric(body.Exp); ok && exp > 0 {
		if exp > 1e12 { // tolerate milliseconds
			exp /= 1000
		}
		if candidate := time.Unix(int64(exp), 0); candidate.After(now) {
			expiry = candidate
		} else {
			// The JWT is valid on the server; our clock is probably ahead.
			// Use the default lifetime and rely on the 401 retry.
			log.Warn().Time("exp", candidate).Msg("stellar cyber: token already expired by the local clock; check the host time")
		}
	}

	t.token = body.AccessToken
	t.refreshAt = expiry.Add(-tokenRefreshMargin)
	return "Bearer " + t.token, nil
}
