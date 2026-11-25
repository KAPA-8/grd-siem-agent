package fortisiem

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	stdlog "log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

func bothProfiles(t *testing.T, fn func(t *testing.T, profile mockProfile)) {
	t.Run("cloud", func(t *testing.T) { fn(t, profileCloud) })
	t.Run("7.4", func(t *testing.T) { fn(t, profile74) })
}

func TestCollect_FirstCycleReadsTheLookbackWindow(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, nil)
		old := securityIncident(1, testBase.Add(-10*24*time.Hour)) // first seen before the lookback...
		old.LastSeen = ms(testBase.Add(-time.Hour))                // ...but still active
		fp := securityIncident(2, testBase.Add(-2*24*time.Hour))
		fp.Status, fp.Reso = "Cleared Manually", "False Positive"
		change := securityIncident(3, testBase.Add(-24*time.Hour))
		change.Category = "Change"
		gone := securityIncident(4, testBase.Add(-8*24*time.Hour)) // last seen before the lookback
		env.mock.add(old, fp, change, gone, securityIncident(5, testBase.Add(-time.Minute)))

		ids, b := env.collect(t, "")
		sameIDs(t, "first cycle", ids, idsOf(1, 2, 5))
		if !b.statusOnly["1"] || b.statusOnly["2"] || b.statusOnly["5"] {
			t.Errorf("statusOnly = %v, want only the incident first seen before the lookback", b.statusOnly)
		}
		if !b.fairExcluded["2"] || b.status["2"] != "manually_cleared/false_positive" || b.status["5"] != "active" {
			t.Errorf("status = %v, fairExcluded = %v", b.status, b.fairExcluded)
		}
		if !b.from.Equal(testBase.Add(-7*24*time.Hour)) || !b.to.Equal(testBase) {
			t.Errorf("window = %s..%s", b.from, b.to)
		}
		if b.fetched != 4 { // 1, 2, 3 (dropped by securityOnly), 5
			t.Errorf("fetched = %d, want 4", b.fetched)
		}
		var cp checkpointState
		if err := json.Unmarshal([]byte(b.checkpoint), &cp); err != nil {
			t.Fatal(err)
		}
		if cp.TS != ms(testBase.Add(-time.Minute)) || len(cp.IDs) != 1 || cp.IDs[0] != "5" || cp.Sweep != ms(testBase) {
			t.Errorf("checkpoint = %+v", cp)
		}

		reqs := env.mock.recorded(incidentPath)
		if len(reqs) != 1 {
			t.Fatalf("incident requests = %d, want 1", len(reqs))
		}
		q := reqs[0].Query
		if q.OrderBy != orderByLastSeen || q.Descending || q.Size != pageSize || q.TimeTo != ms(testBase) || len(q.Fields) != len(incidentFields) {
			t.Errorf("query = %+v", q)
		}
		if reqs[0].ContentType != "application/json" {
			t.Errorf("content type = %q", reqs[0].ContentType)
		}
	})
}

func TestCollect_IncrementalWithOverlap(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, nil)
		env.mock.add(securityIncident(1, testBase.Add(-30*time.Minute)), securityIncident(2, testBase.Add(-5*time.Minute)))
		ids, b := env.collect(t, "")
		sameIDs(t, "cycle 1", ids, idsOf(1, 2))
		cp1 := b.checkpoint

		// 15 minutes later: a new incident, one that showed up late (its
		// lastSeen is inside the overlap) and an update of incident 1.
		env.clock.Advance(15 * time.Minute)
		late := securityIncident(3, testBase.Add(-8*time.Minute))
		env.mock.add(late, securityIncident(4, testBase.Add(10*time.Minute)))
		env.mock.update(1, func(inc *mockIncident) { inc.LastSeen = ms(testBase.Add(9 * time.Minute)) })

		env.mock.resetRequests()
		ids, b = env.collect(t, cp1)
		sameIDs(t, "cycle 2", ids, idsOf(1, 3, 4)) // 2 was delivered with the same lastSeen
		if q := env.mock.recorded(incidentPath)[0].Query; q.TimeFrom != ms(testBase.Add(-15*time.Minute)) {
			t.Errorf("timeFrom = %d, want checkpoint - 10 min", q.TimeFrom)
		}
		if !b.from.Equal(testBase.Add(-15 * time.Minute)) {
			t.Errorf("window from = %s", b.from)
		}
		cp2 := b.checkpoint

		// The delivery failed: the agent asks again from cp1 and gets the same.
		ids, b = env.collect(t, cp1)
		sameIDs(t, "retry of cycle 2", ids, idsOf(1, 3, 4))
		if b.checkpoint != cp2 {
			t.Errorf("checkpoint = %s, want %s", b.checkpoint, cp2)
		}

		// Delivered: nothing new, the overlap is not posted again.
		env.clock.Advance(15 * time.Minute)
		ids, b = env.collect(t, cp2)
		if len(ids) != 0 {
			t.Errorf("cycle 3 resent %v", ids)
		}

		// After a restart (no memory) the overlap is posted once more: the
		// platform counts it as duplicates.
		fresh, err := newCollectorWith(env.coll.settings, env.server.Client(), config.SyncConfig{LookbackDays: 7, MaxAlertsPerSync: 1000, StatusRefreshHours: 6})
		if err != nil {
			t.Fatal(err)
		}
		env.coll = fresh
		env.useClock()
		ids, _ = env.collect(t, b.checkpoint)
		sameIDs(t, "after restart", ids, idsOf(1)) // in the overlap; 4 is in the checkpoint IDs, 3 is older than the overlap
	})
}

func TestCollect_PaginationWithInclusiveEnd(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 5000 })
		env.coll.pageSize = 100
		env.mock.inclusiveEnd = true // size+1 items per page, as FortiSIEM Cloud
		var want []int64
		for i := int64(0); i < 1203; i++ {
			env.mock.add(securityIncident(10000+i, testBase.Add(-time.Duration(1203-i)*time.Minute)))
			want = append(want, 10000+i)
		}
		ids, b := env.collect(t, "")
		sameIDs(t, "all pages", ids, idsOf(want...))
		if len(ids) != 1203 || b.fetched != 1203 {
			t.Errorf("templates = %d, fetched = %d, want 1203 each (no duplicates)", len(ids), b.fetched)
		}
		reqs := env.mock.recorded(incidentPath)
		if len(reqs) != 13 {
			t.Fatalf("pages = %d, want 13", len(reqs))
		}
		for i, r := range reqs {
			if r.Query.Start != i*100 || r.Query.Size != 100 {
				t.Errorf("page %d: start=%d size=%d, want start += size", i, r.Query.Start, r.Query.Size)
			}
		}
	})
}

func TestCollect_MaxAlertsTruncatesAndResumes(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 5 })
		env.coll.pageSize = 4
		var all []int64
		for i := int64(1); i <= 12; i++ {
			inc := securityIncident(i, testBase.Add(-time.Duration(13-i)*time.Hour))
			if i%3 == 0 {
				inc.Category = "Availability" // dropped, but still moves the checkpoint
			} else {
				all = append(all, i)
			}
			env.mock.add(inc)
		}
		var got []string
		checkpoint := ""
		for cycle := 0; cycle < 4; cycle++ {
			ids, b := env.collect(t, checkpoint)
			if len(ids) > 5 {
				t.Fatalf("cycle %d returned %d templates, max 5", cycle, len(ids))
			}
			got = append(got, ids...)
			checkpoint = b.checkpoint
			env.clock.Advance(time.Minute)
		}
		sameIDs(t, "all cycles", got, idsOf(all...))
		if len(got) != len(all) {
			t.Errorf("delivered %d templates, want %d without repeats", len(got), len(all))
		}
	})
}

func TestCollect_Filters(t *testing.T) {
	env := newEnv(t, profileCloud, func(s *settings, c *config.SyncConfig) {
		s.tenantID = "Org Synth B"
		c.Filters.MinSeverity = "high"
	})
	a := securityIncident(1, testBase.Add(-time.Hour))
	a.Severity, a.Customer, a.CustID = 9, "Org Synth A", 2001
	b := securityIncident(2, testBase.Add(-time.Hour))
	b.Severity, b.Customer, b.CustID = 9, "Org Synth B", 2002
	low := b
	low.ID, low.Severity = 3, 5
	byID := b
	byID.ID, byID.Customer = 4, "renamed"
	env.mock.add(a, b, low, byID)
	ids, _ := env.collect(t, "")
	sameIDs(t, "tenant by name and min severity", ids, idsOf(2))

	env2 := newEnv(t, profile74, func(s *settings, _ *config.SyncConfig) { s.tenantID = "2002"; s.securityOnly = false })
	nonSec := byID
	nonSec.ID, nonSec.Category = 5, "Change"
	env2.mock.add(a, b, byID, nonSec)
	ids, _ = env2.collect(t, "")
	sameIDs(t, "tenant by phCustId, all categories", ids, idsOf(2, 4, 5))
}

func TestCollect_StatusSweepRefreshesUnchangedIncidents(t *testing.T) {
	env := newEnv(t, profileCloud, nil)
	env.mock.add(securityIncident(1, testBase.Add(-3*time.Hour)), securityIncident(2, testBase.Add(-2*time.Hour)))
	_, b := env.collect(t, "")
	checkpoint := b.checkpoint

	// An analyst marks incident 1 as a false positive: its lastSeen does not move.
	env.mock.update(1, func(inc *mockIncident) { inc.Status, inc.Reso = "Cleared Manually", "False Positive" })
	env.clock.Advance(time.Hour)
	ids, b := env.collect(t, checkpoint)
	if len(ids) != 0 {
		t.Fatalf("before the sweep is due: %v", ids)
	}
	checkpoint = b.checkpoint

	env.clock.Advance(5 * time.Hour) // 6 h since the first cycle
	env.mock.add(securityIncident(3, testBase.Add(6*time.Hour-time.Minute)))
	ids, b = env.collect(t, checkpoint)
	sameIDs(t, "sweep", ids, idsOf(1, 2, 3))
	if !b.fairExcluded["1"] || b.status["1"] != "manually_cleared/false_positive" || b.statusOnly["1"] {
		t.Errorf("swept incident 1: status %q fairExcluded %v statusOnly %v", b.status["1"], b.fairExcluded["1"], b.statusOnly["1"])
	}
	var cp checkpointState
	_ = json.Unmarshal([]byte(b.checkpoint), &cp)
	if cp.Sweep != ms(testBase.Add(6*time.Hour)) {
		t.Errorf("sweep time = %d", cp.Sweep)
	}
	reqs := env.mock.recorded(incidentPath)
	last := reqs[len(reqs)-1].Query
	if last.TimeFrom != ms(testBase.Add(6*time.Hour-7*24*time.Hour)) {
		t.Errorf("sweep timeFrom = %d, want now - lookback", last.TimeFrom)
	}

	// Disabled with status_refresh_hours: 0.
	off := newEnv(t, profileCloud, func(_ *settings, s *config.SyncConfig) { s.StatusRefreshHours = 0 })
	off.mock.add(securityIncident(1, testBase.Add(-3*time.Hour)))
	_, b = off.collect(t, "")
	off.clock.Advance(48 * time.Hour)
	off.mock.resetRequests()
	ids, _ = off.collect(t, b.checkpoint)
	if len(ids) != 0 || len(off.mock.recorded(incidentPath)) != 1 {
		t.Errorf("sweep ran while disabled: %v", ids)
	}
}

func TestOAuth_TokenIsCachedAndRefreshedOn401(t *testing.T) {
	env := newEnv(t, profileCloud, nil)
	env.coll.pageSize = 2
	for i := int64(1); i <= 5; i++ {
		env.mock.add(securityIncident(i, testBase.Add(-time.Duration(i)*time.Minute)))
	}
	if err := env.coll.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	ids, _ := env.collect(t, "")
	if len(ids) != 5 || env.mock.tokenExchanges() != 1 {
		t.Fatalf("templates = %d, token exchanges = %d, want 5 and 1", len(ids), env.mock.tokenExchanges())
	}
	for _, r := range env.mock.recorded(tokenPath) {
		if r.Method != http.MethodPost || r.ContentType != "application/x-www-form-urlencoded" {
			t.Errorf("token request %s %s", r.Method, r.ContentType)
		}
	}
	env.mock.revokeTokens()
	if err := env.coll.HealthCheck(context.Background()); err != nil {
		t.Fatalf("after revocation: %v", err)
	}
	if env.mock.tokenExchanges() != 2 {
		t.Errorf("token exchanges = %d, want a refresh after the 401", env.mock.tokenExchanges())
	}
	// Refreshed before expires_in (24 h) minus 60 s.
	env.clock.Advance(24*time.Hour - 30*time.Second)
	if err := env.coll.HealthCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	if env.mock.tokenExchanges() != 3 {
		t.Errorf("token exchanges = %d, want a refresh near expiry", env.mock.tokenExchanges())
	}
}

func TestOAuth_GetFallbackOnlyAfter404Or405(t *testing.T) {
	env := newEnv(t, profileCloud, nil)
	env.mock.tokenPostStatus = http.StatusMethodNotAllowed
	env.mock.tokenGetJSON = true
	if err := env.coll.HealthCheck(context.Background()); err != nil {
		t.Fatal(err)
	}
	reqs := env.mock.recorded(tokenPath)
	if len(reqs) != 2 || reqs[0].Method != http.MethodPost || reqs[1].Method != http.MethodGet {
		t.Errorf("token requests = %+v", reqs)
	}

	// GET answering the Tomcat HTML page is reported, never parsed.
	env2 := newEnv(t, profileCloud, nil)
	env2.mock.tokenPostStatus = http.StatusNotFound
	err := env2.coll.HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no devolvió JSON") || !strings.Contains(err.Error(), "requiere 7.5+") {
		t.Errorf("err = %v", err)
	}
}

func TestOAuth_AgainstFortiSIEM74(t *testing.T) {
	env := newEnv(t, profile74, func(s *settings, _ *config.SyncConfig) {
		*s = settings{baseURL: s.baseURL, deployment: deploymentOnPrem, authMode: authModeOAuth, clientID: testClientID, clientSecret: testSecret}
	})
	err := env.coll.Init(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no tiene tokens OAuth (requiere 7.5+): usa usuario y contraseña") {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), testSecret) {
		t.Error("the error leaks the client secret")
	}
}

func TestOAuth_TransientInvalidInputIsRetried(t *testing.T) {
	env := newEnv(t, profileCloud, nil)
	env.mock.tokenTransient400 = 1
	if err := env.coll.HealthCheck(context.Background()); err != nil {
		t.Fatalf("a transient 400 must be retried: %v", err)
	}
	if n := len(env.mock.recorded(tokenPath)); n != 2 {
		t.Errorf("token requests = %d, want 2", n)
	}

	persistent := newEnv(t, profileCloud, nil)
	persistent.mock.tokenTransient400 = 10
	err := persistent.coll.HealthCheck(context.Background())
	if err == nil || !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("err = %v", err)
	}
	if n := len(persistent.mock.recorded(tokenPath)); n != 1+tokenTransientRetries {
		t.Errorf("token requests = %d, want %d", n, 1+tokenTransientRetries)
	}
}

func TestOAuth_InvalidClient(t *testing.T) {
	env := newEnv(t, profileCloud, func(s *settings, _ *config.SyncConfig) { s.clientSecret = "wrong-secret-value" })
	err := env.coll.Init(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("err = %v", err)
	}
}

func TestBasic_SpecialCharactersAndOrganizationPrefix(t *testing.T) {
	env := newEnv(t, profile74, nil)
	env.mock.add(securityIncident(1, testBase.Add(-time.Hour)))
	if err := env.coll.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	authz := env.mock.recorded(incidentPath)[0].Authorization
	decoded, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(authz, "Basic "))
	if string(decoded) != `super/apiuser:p:a$s"w'o@r/d` {
		t.Errorf("basic credentials = %q", decoded)
	}
	// A username that already has the prefix is sent as-is.
	if got := basicUser("", "super/apiuser"); got != "super/apiuser" {
		t.Errorf("basicUser = %q", got)
	}
	if got := basicUser("", "apiuser"); got != "super/apiuser" {
		t.Errorf("default organization: %q", got)
	}

	// Without the organization prefix FortiSIEM answers 401.
	noPrefix := newEnv(t, profile74, func(s *settings, _ *config.SyncConfig) { s.organization = "Org Synth A" })
	err := noPrefix.coll.Init(context.Background())
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "prefijo de su organización") || !strings.Contains(err.Error(), "super/<usuario>") {
		t.Errorf("err = %v", err)
	}
	if strings.Contains(err.Error(), testPassword) {
		t.Error("the error leaks the password")
	}
	if !strings.Contains(err.Error(), "HTML") {
		t.Errorf("the HTML body should be summarized, err = %v", err)
	}
}

func TestClient_RetriesWithRetryAfter(t *testing.T) {
	env := newEnv(t, profile74, nil)
	env.mock.add(securityIncident(1, testBase.Add(-time.Hour)))
	env.mock.failNext(http.StatusTooManyRequests, "7")
	env.mock.failNext(http.StatusServiceUnavailable, "")
	ids, _ := env.collect(t, "")
	sameIDs(t, "after retries", ids, idsOf(1))
	if len(env.sleeps) != 2 || env.sleeps[0] != 7*time.Second || env.sleeps[1] != 2*time.Second {
		t.Errorf("sleeps = %v, want [7s 2s]", env.sleeps)
	}

	for range defaultMaxRetries + 1 {
		env.mock.failNext(http.StatusTooManyRequests, "1")
	}
	if _, err := env.coll.Collect(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "HTTP 429") {
		t.Errorf("err = %v, want the 429 after the last retry", err)
	}
}

func TestCollect_FallsBackWhenOrderByLastSeenIsRejected(t *testing.T) {
	env := newEnv(t, profile74, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 2 })
	env.mock.rejectOrderByLastSeen = true
	for i := int64(1); i <= 4; i++ {
		env.mock.add(securityIncident(i, testBase.Add(-time.Duration(i)*time.Hour)))
	}
	ids, _ := env.collect(t, "")
	// Unsorted on lastSeen: the whole window is read whatever max_alerts_per_sync says.
	sameIDs(t, "fallback", ids, idsOf(1, 2, 3, 4))
	if env.coll.orderBy != orderByFirstSeen {
		t.Errorf("orderBy = %s", env.coll.orderBy)
	}
}

func TestCollect_HTMLAnswerIsAClearError(t *testing.T) {
	env := newEnv(t, profileCloud, nil)
	env.mock.htmlIncidents = true
	_, err := env.coll.Collect(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "no es JSON") || !strings.Contains(err.Error(), "siem.api_url") {
		t.Errorf("err = %v", err)
	}
}

func TestTestConnection(t *testing.T) {
	env := newEnv(t, profile74, nil)
	env.mock.add(securityIncident(1, testBase.Add(-time.Hour)), securityIncident(2, testBase.Add(-30*time.Hour)))
	msg, err := env.coll.TestConnection(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "conexión correcta") || !strings.Contains(msg, "24 h: 1") {
		t.Errorf("message = %q", msg)
	}
}

// --- TLS -----------------------------------------------------------------------

func TestTLS_SelfSignedSupervisor(t *testing.T) {
	clock := &fakeClock{t: testBase}
	mock := newMockFortiSIEM(t, clock, profile74)
	server := httptest.NewUnstartedServer(mock)
	server.Config.ErrorLog = stdlog.New(io.Discard, "", 0) // the refused handshakes
	server.StartTLS()
	t.Cleanup(server.Close)

	base := config.SIEMConfig{
		Type: Name, APIURL: server.URL, Deployment: deploymentOnPrem,
		Credentials: config.CredentialConfig{Organization: testOrg, Username: testUser, Password: testPassword, ValidateSSL: true},
	}
	syncCfg := config.SyncConfig{LookbackDays: 7, MaxAlertsPerSync: 100}

	coll, err := newCollector(base, syncCfg)
	if err != nil {
		t.Fatal(err)
	}
	err = coll.Init(context.Background())
	if err == nil || !strings.Contains(err.Error(), "huella SHA-256") || !strings.Contains(err.Error(), "ca_cert_file") {
		t.Fatalf("err = %v", err)
	}

	caFile := filepath.Join(t.TempDir(), "supervisor.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	withCA := base
	withCA.Credentials.CACertFile = caFile
	coll, err = newCollector(withCA, syncCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := coll.Init(context.Background()); err != nil {
		t.Errorf("with ca_cert_file: %v", err)
	}

	insecure := base
	insecure.Credentials.ValidateSSL = false
	coll, err = newCollector(insecure, syncCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := coll.Init(context.Background()); err != nil {
		t.Errorf("with validate_ssl false: %v", err)
	}

	// FortiSIEM Cloud ignores validate_ssl: false.
	cloud := insecure
	cloud.Deployment = deploymentCloud
	coll, err = newCollector(cloud, syncCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := coll.Init(context.Background()); err == nil {
		t.Error("cloud must verify the certificate even with validate_ssl: false")
	}
}

// --- checkpoint -------------------------------------------------------------------

func TestParseCheckpoint(t *testing.T) {
	for _, raw := range []string{"", "1700000000", `{"v":1,"mode":"alerts","ts":5,"ids":[]}`, `{"v":2,"mode":"incidents","ts":5}`, `{"v":1,"mode":"incidents","ts":0}`, "garbage"} {
		if _, ok := parseCheckpoint(raw, testBase); ok {
			t.Errorf("%q accepted", raw)
		}
	}
	future := `{"v":1,"mode":"incidents","ts":` + jsonInt(ms(testBase.Add(25*time.Hour))) + `}`
	if _, ok := parseCheckpoint(future, testBase); ok {
		t.Error("far-future checkpoint accepted")
	}
	cp, ok := parseCheckpoint(`{"v":1,"mode":"incidents","ts":5,"ids":["9"],"sweep":3}`, testBase)
	if !ok || cp.TS != 5 || cp.Sweep != 3 || len(cp.IDs) != 1 {
		t.Errorf("cp = %+v ok = %v", cp, ok)
	}
}

func jsonInt(n int64) string {
	data, _ := json.Marshal(n)
	return string(data)
}

// After a restart the in-memory overlap memo is gone, so the overlap before
// the checkpoint is posted again. It must not use up max_alerts_per_sync:
// otherwise a pass truncated inside the overlap never moves the checkpoint
// and collection stalls for good.
func TestCollect_RestartWithAFullOverlapStillAdvances(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, nil)
		for i := int64(1); i <= 5; i++ {
			env.mock.add(securityIncident(i, testBase.Add(-time.Duration(10-i)*time.Minute)))
		}
		ids, b := env.collect(t, "")
		sameIDs(t, "before the restart", ids, idsOf(1, 2, 3, 4, 5))
		checkpoint := b.checkpoint

		fresh, err := newCollectorWith(env.coll.settings, env.server.Client(), config.SyncConfig{LookbackDays: 7, MaxAlertsPerSync: 3, StatusRefreshHours: 6})
		if err != nil {
			t.Fatal(err)
		}
		env.coll = fresh
		env.useClock()
		env.clock.Advance(time.Minute)
		for i := int64(100); i <= 103; i++ {
			env.mock.add(securityIncident(i, testBase.Add(time.Duration(i-99)*time.Second)))
		}

		var got []string
		for cycle := 0; cycle < 4; cycle++ {
			ids, b := env.collect(t, checkpoint)
			for _, id := range ids {
				if len(id) == 3 { // 100..103
					got = append(got, id)
				}
			}
			checkpoint = b.checkpoint
			env.clock.Advance(time.Minute)
		}
		sameIDs(t, "new incidents after the restart", got, idsOf(100, 101, 102, 103))
	})
}

// The status sweep reads the whole lookback window; the incidents it could
// insert stay within max_alerts_per_sync (the rest only refresh the status).
func TestCollect_StatusSweepRespectsMaxAlerts(t *testing.T) {
	env := newEnv(t, profileCloud, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 2 })
	for i := int64(1); i <= 10; i++ {
		env.mock.add(securityIncident(i, testBase.Add(-time.Duration(11-i)*time.Hour)))
	}
	ids, b := env.collect(t, "")
	sameIDs(t, "cycle 1", ids, idsOf(1, 2))

	env.clock.Advance(6 * time.Hour)
	ids, b = env.collect(t, b.checkpoint)
	insertable := 0
	for _, id := range ids {
		if !b.statusOnly[id] && !b.fairExcluded[id] {
			insertable++
		}
	}
	if insertable > 2 {
		t.Errorf("sweep cycle: %d insertable alerts of %d, max_alerts_per_sync is 2 (statusOnly %v)", insertable, len(ids), b.statusOnly)
	}
	sameIDs(t, "sweep cycle", ids, idsOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
	if b.statusOnly["3"] || b.statusOnly["4"] || !b.statusOnly["5"] || !b.statusOnly["1"] {
		t.Errorf("statusOnly = %v, want the incremental 3 and 4 insertable and the sweep only status", b.statusOnly)
	}
}

// A 400 from the token endpoint is a credential (or transient) error, never
// a reason to stop sorting by incidentLastSeen.
func TestCollect_Token400KeepsTheLastSeenSort(t *testing.T) {
	env := newEnv(t, profileCloud, nil)
	env.mock.add(securityIncident(1, testBase.Add(-time.Hour)))
	env.mock.tokenPostStatus = http.StatusBadRequest
	if _, err := env.coll.Collect(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "HTTP 400") {
		t.Fatalf("err = %v", err)
	}
	if env.coll.orderBy != orderByLastSeen {
		t.Fatalf("orderBy = %s after a token 400", env.coll.orderBy)
	}
	env.mock.tokenPostStatus = 0
	ids, _ := env.collect(t, "")
	sameIDs(t, "after the token recovers", ids, idsOf(1))
	for _, r := range env.mock.recorded(incidentPath) {
		if r.Query.OrderBy != orderByLastSeen {
			t.Errorf("query sorted by %s", r.Query.OrderBy)
		}
	}
}
