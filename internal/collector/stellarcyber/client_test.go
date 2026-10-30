package stellarcyber

import (
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

func TestAuth_APITokenExchangesBasicForJWT(t *testing.T) {
	env := newSaaSEnv(t, nil)
	if err := env.coll.client.probeAlerts(context.Background()); err != nil {
		t.Fatal(err)
	}
	tokenReqs := env.mock.recorded(tokenPath)
	if len(tokenReqs) != 1 {
		t.Fatalf("token requests = %d, want 1", len(tokenReqs))
	}
	if tokenReqs[0].Method != http.MethodPost || tokenReqs[0].Authorization != basicHeader(testEmail, testAPIToken) ||
		tokenReqs[0].ContentType != "application/x-www-form-urlencoded" || tokenReqs[0].BodyLen > 0 {
		t.Errorf("unexpected token request: %+v", tokenReqs[0])
	}
	search := env.mock.recorded(searchPath)
	if len(search) != 1 || search[0].Authorization != "Bearer jwt-1" {
		t.Fatalf("search requests = %+v", search)
	}
	if search[0].Query.Get("q") != "fidelity:<0" || search[0].Query.Get("size") != "0" {
		t.Errorf("probe query = %v", search[0].Query)
	}
}

func TestAuth_ScopedKeyUsesBearer(t *testing.T) {
	env := newSaaSEnv(t, func(s *settings, _ *config.SyncConfig) {
		s.authMode, s.username, s.apiKey = authModeScopedKey, "", testScopedKey
	})
	if err := env.coll.client.probeAlerts(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := env.mock.recorded(tokenPath)[0].Authorization; got != "Bearer "+testScopedKey {
		t.Errorf("token exchange Authorization = %q", got)
	}
}

func TestAuth_RefreshBeforeExpiry(t *testing.T) {
	env := newSaaSEnv(t, nil)
	ctx := context.Background()
	probe := func() {
		t.Helper()
		if err := env.coll.client.probeAlerts(ctx); err != nil {
			t.Fatal(err)
		}
	}

	probe()
	env.clock.Advance(8*time.Minute + 59*time.Second) // exp - 61s: still cached
	probe()
	if n := env.mock.tokenExchanges(); n != 1 {
		t.Fatalf("token exchanges = %d, want 1 (token still valid)", n)
	}
	env.clock.Advance(2 * time.Second) // exp - 59s: refresh
	probe()
	if n := env.mock.tokenExchanges(); n != 2 {
		t.Fatalf("token exchanges = %d, want 2 after reaching exp-60s", n)
	}
	search := env.mock.recorded(searchPath)
	if search[len(search)-1].Authorization != "Bearer jwt-2" {
		t.Errorf("last call used %q, want the refreshed token", search[len(search)-1].Authorization)
	}
}

func TestAuth_MissingExpAssumes600Seconds(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.mock.omitExp = true
	ctx := context.Background()
	if err := env.coll.client.probeAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	env.clock.Advance(538 * time.Second)
	if err := env.coll.client.probeAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	if n := env.mock.tokenExchanges(); n != 1 {
		t.Fatalf("token exchanges = %d, want 1", n)
	}
	env.clock.Advance(3 * time.Second) // 541s >= 600-60
	if err := env.coll.client.probeAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	if n := env.mock.tokenExchanges(); n != 2 {
		t.Fatalf("token exchanges = %d, want 2", n)
	}
}

func TestAuth_RefreshOn401AndRetryOnce(t *testing.T) {
	env := newSaaSEnv(t, nil)
	ctx := context.Background()
	if err := env.coll.client.probeAlerts(ctx); err != nil {
		t.Fatal(err)
	}
	env.mock.revokeTokens() // e.g. key rotated server-side
	env.mock.resetRequests()
	if err := env.coll.client.probeAlerts(ctx); err != nil {
		t.Fatalf("expected the 401 to be recovered: %v", err)
	}
	search := env.mock.recorded(searchPath)
	if len(search) != 2 || search[0].Authorization != "Bearer jwt-1" || search[1].Authorization != "Bearer jwt-2" {
		t.Errorf("search attempts = %+v", search)
	}
	if n := env.mock.tokenExchanges(); n != 2 {
		t.Errorf("token exchanges = %d, want 2", n)
	}
}

func TestAuth_Second401IsAnError(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.mock.failNext(searchPath, http.StatusUnauthorized, "")
	env.mock.failNext(searchPath, http.StatusUnauthorized, "")
	err := env.coll.client.probeAlerts(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("err = %v, want APIError 401", err)
	}
	if n := len(env.mock.recorded(searchPath)); n != 2 {
		t.Errorf("search attempts = %d, want 2 (one retry)", n)
	}
}

func TestAuth_InvalidCredentials(t *testing.T) {
	env := newSaaSEnv(t, func(s *settings, _ *config.SyncConfig) { s.username = "API@acme.com" })
	err := env.coll.client.probeAlerts(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "case-sensitive") {
		t.Fatalf("err = %v", err)
	}
	if n := len(env.mock.recorded(searchPath)); n != 0 {
		t.Errorf("data calls = %d, want 0", n)
	}
}

func TestAuth_ConcurrentRefreshIsCoalesced(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.mock.exchangeDelay = 50 * time.Millisecond
	var wg sync.WaitGroup
	headers := make([]string, 8)
	errs := make([]error, 8)
	for i := range headers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			headers[i], errs[i] = env.coll.client.auth.header(context.Background())
		}(i)
	}
	wg.Wait()
	for i := range headers {
		if errs[i] != nil || headers[i] != "Bearer jwt-1" {
			t.Errorf("caller %d got %q, %v", i, headers[i], errs[i])
		}
	}
	if n := env.mock.tokenExchanges(); n != 1 {
		t.Errorf("token exchanges = %d, want 1", n)
	}
}

func TestAuth_WaiterHonoursContext(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.mock.exchangeDelay = 300 * time.Millisecond
	go func() { _, _ = env.coll.client.auth.header(context.Background()) }()
	time.Sleep(50 * time.Millisecond) // let the first caller start the exchange
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := env.coll.client.auth.header(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline exceeded while waiting for the refresh", err)
	}
}

func TestAuth_LegacyBasicFallbackOnPrem(t *testing.T) {
	env := newSaaSEnv(t, func(s *settings, _ *config.SyncConfig) { s.deployment = deploymentOnPrem })
	env.mock.legacyBasic = true
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := env.coll.client.probeAlerts(ctx); err != nil {
			t.Fatalf("probe %d: %v", i, err)
		}
	}
	for _, r := range env.mock.recorded(searchPath) {
		if r.Authorization != basicHeader(testEmail, testAPIToken) {
			t.Errorf("data call Authorization = %q, want Basic", r.Authorization)
		}
	}
	if n := env.mock.tokenExchanges(); n != 1 {
		t.Errorf("token endpoint probed %d times, want 1", n)
	}
}

func TestAuth_NoLegacyFallbackForSaaSOrScopedKeys(t *testing.T) {
	cases := map[string]func(*settings, *config.SyncConfig){
		"saas": nil,
		"onprem scoped_key": func(s *settings, _ *config.SyncConfig) {
			s.deployment, s.authMode, s.username, s.apiKey = deploymentOnPrem, authModeScopedKey, "", testScopedKey
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			env := newSaaSEnv(t, mutate)
			env.mock.legacyBasic = true
			err := env.coll.client.probeAlerts(context.Background())
			if err == nil || !strings.Contains(err.Error(), "HTTP 404") || !strings.Contains(err.Error(), "token endpoint not found") {
				t.Fatalf("err = %v, want token endpoint 404", err)
			}
			if n := len(env.mock.recorded(searchPath)); n != 0 {
				t.Errorf("data calls = %d, want 0 (no per-call Basic)", n)
			}
		})
	}
}

func TestClient_RetriesTransientStatusesWithBackoff(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.mock.failNext(searchPath, http.StatusServiceUnavailable, "")
	env.mock.failNext(searchPath, http.StatusTooManyRequests, "7")
	env.mock.failNext(searchPath, http.StatusGatewayTimeout, "")
	if err := env.coll.client.probeAlerts(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []time.Duration{time.Second, 7 * time.Second, 4 * time.Second}
	if len(env.sleeps) != len(want) {
		t.Fatalf("sleeps = %v, want %v", env.sleeps, want)
	}
	for i := range want {
		if env.sleeps[i] != want[i] {
			t.Errorf("sleep %d = %v, want %v", i, env.sleeps[i], want[i])
		}
	}
}

func TestClient_GivesUpAfterThreeRetries(t *testing.T) {
	env := newSaaSEnv(t, nil)
	for i := 0; i < 4; i++ {
		env.mock.failNext(searchPath, http.StatusBadGateway, "")
	}
	err := env.coll.client.probeAlerts(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("err = %v, want APIError 502", err)
	}
	if n := len(env.mock.recorded(searchPath)); n != 4 {
		t.Errorf("attempts = %d, want 4", n)
	}
}

func TestClient_DoesNotRetryOtherErrors(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadRequest, http.StatusNotFound} {
		env := newSaaSEnv(t, nil)
		env.mock.failNext(searchPath, status, "")
		if err := env.coll.client.probeAlerts(context.Background()); err == nil {
			t.Errorf("status %d: expected an error", status)
		}
		if n := len(env.mock.recorded(searchPath)); n != 1 {
			t.Errorf("status %d: attempts = %d, want 1", status, n)
		}
	}
}

func TestClient_RetryAfterParsingAndCap(t *testing.T) {
	env := newSaaSEnv(t, nil)
	c := env.coll.client
	if got := c.retryDelay(0, "3600"); got != defaultMaxRetryWait {
		t.Errorf("Retry-After 3600 = %v, want cap %v", got, defaultMaxRetryWait)
	}
	date := env.clock.Now().Add(30 * time.Second).UTC().Format(http.TimeFormat)
	if got := c.retryDelay(0, date); got != 30*time.Second {
		t.Errorf("Retry-After date = %v, want 30s", got)
	}
	if got := c.retryDelay(1, "soon"); got != 2*time.Second {
		t.Errorf("invalid Retry-After = %v, want exponential 2s", got)
	}
	if got := c.retryDelay(2, ""); got != 4*time.Second {
		t.Errorf("attempt 2 = %v, want 4s", got)
	}
}

func TestClient_ForbiddenSearchExplainsDataSource(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.mock.forbidSearch = true
	err := env.coll.Init(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 403") || !strings.Contains(err.Error(), "data_source: cases") {
		t.Fatalf("err = %v", err)
	}
}

// --- TLS (on-prem self-signed, SaaS always verifies) ---------------------------------

func newTLSMock(t *testing.T) (*mockStellar, *httptest.Server, string) {
	t.Helper()
	mock := newMockStellar(t, newFakeClock(time.Now()))
	server := httptest.NewTLSServer(mock)
	t.Cleanup(server.Close)
	caFile := filepath.Join(t.TempDir(), "dp-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return mock, server, caFile
}

func tlsConfig(url, deployment string, validateSSL bool, caFile string) config.SIEMConfig {
	return config.SIEMConfig{
		Type:       Name,
		APIURL:     url,
		Deployment: deployment,
		Credentials: config.CredentialConfig{
			Username:    testEmail,
			APIKey:      testAPIToken,
			ValidateSSL: validateSSL,
			CACertFile:  caFile,
		},
	}
}

func TestTLS_OnPremSelfSigned(t *testing.T) {
	_, server, caFile := newTLSMock(t)
	syncCfg := config.SyncConfig{LookbackDays: 7, MaxAlertsPerSync: 100}

	tests := []struct {
		name        string
		validateSSL bool
		caFile      string
		wantErr     string
	}{
		{"verification fails by default", true, "", "TLS certificate verification failed"},
		{"skip verify works", false, "", ""},
		{"CA file works", true, caFile, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coll, err := New(tlsConfig(server.URL, "onprem", tt.validateSSL, tt.caFile), syncCfg)
			if err != nil {
				t.Fatal(err)
			}
			err = coll.Init(context.Background())
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Init: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) || !strings.Contains(err.Error(), "ca_cert_file") {
				t.Fatalf("Init err = %v, want %q with a ca_cert_file hint", err, tt.wantErr)
			}
		})
	}
}

func TestTLS_SaaSAlwaysVerifies(t *testing.T) {
	_, server, caFile := newTLSMock(t)
	syncCfg := config.SyncConfig{LookbackDays: 7, MaxAlertsPerSync: 100}

	coll, err := New(tlsConfig(server.URL, "saas", false, ""), syncCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := coll.Init(context.Background()); err == nil || !strings.Contains(err.Error(), "TLS certificate verification failed") {
		t.Fatalf("SaaS with validate_ssl: false must still verify; err = %v", err)
	}

	coll, err = New(tlsConfig(server.URL, "saas", false, caFile), syncCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := coll.Init(context.Background()); err != nil {
		t.Fatalf("SaaS with a trusted CA: %v", err)
	}
}

func TestNew_CAFileErrors(t *testing.T) {
	cfg := tlsConfig("https://dp.local", "onprem", true, filepath.Join(t.TempDir(), "missing.pem"))
	if _, err := New(cfg, config.SyncConfig{}); err == nil || !strings.Contains(err.Error(), "ca_cert_file") {
		t.Errorf("err = %v", err)
	}
}
