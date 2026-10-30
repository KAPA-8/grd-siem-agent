package stellarcyber

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/config"
)

func ms(t time.Time) int64 { return t.UnixMilli() }

func mustCollect(t *testing.T, c *Collector, checkpoint string) collector.Batch {
	t.Helper()
	batch, err := c.Collect(context.Background(), checkpoint)
	if err != nil {
		t.Fatalf("Collect(%q): %v", checkpoint, err)
	}
	return batch
}

func externalIDs(b collector.Batch) []string {
	ids := []string{}
	for _, tmpl := range b.Templates {
		ids = append(ids, tmpl.ExternalID)
	}
	return ids
}

func decodeCheckpoint(t *testing.T, raw string) checkpointState {
	t.Helper()
	var cp checkpointState
	if err := json.Unmarshal([]byte(raw), &cp); err != nil {
		t.Fatalf("checkpoint %q is not JSON: %v", raw, err)
	}
	return cp
}

func checkpointJSON(mode string, ts int64, ids ...string) string {
	if ids == nil {
		ids = []string{}
	}
	data, _ := json.Marshal(checkpointState{V: 1, Mode: mode, TS: ts, IDs: ids})
	return string(data)
}

func TestCollectAlerts_FirstRunWindowQueryAndLag(t *testing.T) {
	env := newSaaSEnv(t, nil)
	now := env.clock.Now()
	tooOld := ms(now.Add(-8 * 24 * time.Hour))
	a1 := ms(now.Add(-3 * 24 * time.Hour))
	a2 := ms(now.Add(-24 * time.Hour))
	fresh := ms(now.Add(-60 * time.Second)) // inside the 120s stability lag
	env.addAlerts(alertHit("old", tooOld, 50), alertHit("a2", a2, 50), alertHit("a1", a1, 50), alertHit("fresh", fresh, 50))

	batch := mustCollect(t, env.coll, "")
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"a1", "a2"}) {
		t.Fatalf("collected %v, want [a1 a2]", got)
	}
	lower, upper := ms(now.Add(-7*24*time.Hour)), ms(now.Add(-120*time.Second))
	if ms(batch.WindowFrom) != lower || ms(batch.WindowTo) != upper {
		t.Errorf("window = [%v, %v), want [%d, %d)", batch.WindowFrom, batch.WindowTo, lower, upper)
	}
	if batch.Checkpoint != checkpointJSON("alerts", a2, "a2") {
		t.Errorf("checkpoint = %s", batch.Checkpoint)
	}
	if batch.Fetched != 2 || batch.DuplicatesRemoved != 0 {
		t.Errorf("fetched/dups = %d/%d", batch.Fetched, batch.DuplicatesRemoved)
	}

	reqs := env.mock.recorded(searchPath)
	if len(reqs) != 1 {
		t.Fatalf("search requests = %d", len(reqs))
	}
	q := reqs[0].Query
	wantQ := fmt.Sprintf(`write_time:[%d TO %d} AND NOT event_status:"Ignored"`, lower, upper)
	if q.Get("q") != wantQ || q.Get("sort") != "write_time:asc" || q.Get("from") != "0" || q.Get("size") != "500" || q.Get("track_total_hits") != "true" {
		t.Errorf("query = %v\nwant q = %s", q, wantQ)
	}

	// Two minutes later the fresh alert is outside the lag and is collected.
	env.clock.Advance(2 * time.Minute)
	batch = mustCollect(t, env.coll, batch.Checkpoint)
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"fresh"}) {
		t.Fatalf("second cycle collected %v, want [fresh]", got)
	}
	if ms(batch.WindowFrom) != a2 {
		t.Errorf("second window starts at %d, want the checkpoint %d", ms(batch.WindowFrom), a2)
	}
}

// Alerts sharing the boundary write_time are neither lost nor re-sent.
func TestCollectAlerts_CheckpointTieBreak(t *testing.T) {
	env := newSaaSEnv(t, func(_ *settings, sc *config.SyncConfig) { sc.MaxAlertsPerSync = 2 })
	base := ms(env.clock.Now().Add(-time.Hour))
	t1, t2, t3 := base, base+1000, base+2000
	env.addAlerts(alertHit("A", t1, 50), alertHit("B", t2, 50), alertHit("C", t2, 50), alertHit("D", t2, 50), alertHit("E", t3, 50))

	steps := []struct {
		want       []string
		checkpoint string
	}{
		{[]string{"A", "B"}, checkpointJSON("alerts", t2, "B")},
		{[]string{"C", "D"}, checkpointJSON("alerts", t2, "B", "C", "D")},
		{[]string{"E"}, checkpointJSON("alerts", t3, "E")},
	}
	cp := checkpointJSON("alerts", t1-1)
	for i, step := range steps {
		batch := mustCollect(t, env.coll, cp)
		if got := externalIDs(batch); !reflect.DeepEqual(got, step.want) {
			t.Fatalf("step %d collected %v, want %v", i, got, step.want)
		}
		if batch.Checkpoint != step.checkpoint {
			t.Fatalf("step %d checkpoint = %s, want %s", i, batch.Checkpoint, step.checkpoint)
		}
		cp = batch.Checkpoint
	}
	batch := mustCollect(t, env.coll, cp)
	if len(batch.Templates) != 0 || batch.Checkpoint != cp {
		t.Errorf("idle cycle: %v / %s, want nothing and the same checkpoint", externalIDs(batch), batch.Checkpoint)
	}
}

func TestCollectAlerts_PagingRespectsCap(t *testing.T) {
	env := newSaaSEnv(t, func(_ *settings, sc *config.SyncConfig) { sc.MaxAlertsPerSync = 5 })
	env.coll.pageSize = 3
	base := ms(env.clock.Now().Add(-time.Hour))
	for i := 1; i <= 8; i++ {
		env.addAlerts(alertHit("d"+strconv.Itoa(i), base+int64(i), 50))
	}

	batch := mustCollect(t, env.coll, "")
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"d1", "d2", "d3", "d4", "d5"}) {
		t.Fatalf("collected %v", got)
	}
	var sizes, froms []string
	for _, r := range env.mock.recorded(searchPath) {
		sizes = append(sizes, r.Query.Get("size"))
		froms = append(froms, r.Query.Get("from"))
	}
	if !reflect.DeepEqual(sizes, []string{"3", "2"}) || !reflect.DeepEqual(froms, []string{"0", "3"}) {
		t.Errorf("pages size=%v from=%v, want [3 2] [0 3]", sizes, froms)
	}

	env.mock.resetRequests()
	batch = mustCollect(t, env.coll, batch.Checkpoint)
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"d6", "d7", "d8"}) {
		t.Fatalf("second cycle collected %v", got)
	}
	if cp := decodeCheckpoint(t, batch.Checkpoint); cp.TS != base+8 || !reflect.DeepEqual(cp.IDs, []string{"d8"}) {
		t.Errorf("checkpoint = %+v", cp)
	}
}

// from+size never exceeds 10000; a larger backlog continues next cycle.
func TestCollectAlerts_ResultWindowOf10000(t *testing.T) {
	env := newSaaSEnv(t, func(_ *settings, sc *config.SyncConfig) { sc.MaxAlertsPerSync = 10000 })
	base := ms(env.clock.Now().Add(-48 * time.Hour))
	hits := make([]Hit, 10050)
	for i := range hits {
		hits[i] = alertHit(fmt.Sprintf("w%05d", i), base+int64(i)*1000, 50)
	}
	env.addAlerts(hits...)

	batch := mustCollect(t, env.coll, "")
	if len(batch.Templates) != 10000 {
		t.Fatalf("collected %d, want 10000", len(batch.Templates))
	}
	reqs := env.mock.recorded(searchPath)
	if len(reqs) != 20 {
		t.Errorf("search requests = %d, want 20 pages of 500", len(reqs))
	}
	for _, r := range reqs {
		from, _ := strconv.Atoi(r.Query.Get("from"))
		size, _ := strconv.Atoi(r.Query.Get("size"))
		if from+size > 10000 || size > 500 {
			t.Fatalf("request from=%d size=%d exceeds the window", from, size)
		}
	}
	if cp := decodeCheckpoint(t, batch.Checkpoint); cp.TS != base+9999*1000 || !reflect.DeepEqual(cp.IDs, []string{"w09999"}) {
		t.Errorf("checkpoint = %+v", cp)
	}

	batch = mustCollect(t, env.coll, batch.Checkpoint)
	if len(batch.Templates) != 50 || batch.Templates[0].ExternalID != "w10000" {
		t.Fatalf("second cycle collected %d starting at %v", len(batch.Templates), externalIDs(batch)[:1])
	}
}

// When every reachable result was already delivered at the checkpoint ts,
// the collector steps past that millisecond instead of stalling forever.
func TestCollectAlerts_WindowExhaustedAtCheckpointTimestamp(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.coll.maxResultWindow = 4
	ts := ms(env.clock.Now().Add(-time.Hour))
	for i := 1; i <= 6; i++ {
		env.addAlerts(alertHit("s"+strconv.Itoa(i), ts, 50))
	}
	cp := checkpointJSON("alerts", ts, "s1", "s2", "s3", "s4")
	batch := mustCollect(t, env.coll, cp)
	if len(batch.Templates) != 0 {
		t.Fatalf("collected %v", externalIDs(batch))
	}
	if got := decodeCheckpoint(t, batch.Checkpoint); got.TS != ts+1 || len(got.IDs) != 0 {
		t.Errorf("checkpoint = %+v, want ts+1 with no ids", got)
	}
}

func TestCollectAlerts_FiltersSentToServer(t *testing.T) {
	env := newSaaSEnv(t, func(s *settings, sc *config.SyncConfig) {
		s.tenantID = "tenantA"
		sc.Filters.MinSeverity = "medium"
	})
	ts := ms(env.clock.Now().Add(-time.Hour))
	ignored := alertHit("ignored", ts+1, 90)
	ignored.Source["event_status"] = "Ignored"
	noStatus := alertHit("no-status", ts+2, 40)
	delete(noStatus.Source, "event_status")
	otherTenant := alertHit("tenantB", ts+3, 90)
	otherTenant.Source["tenantid"] = "tenantB"
	env.addAlerts(alertHit("low", ts, 39.99), ignored, noStatus, otherTenant, alertHit("ok", ts+4, 80))

	batch := mustCollect(t, env.coll, "")
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"no-status", "ok"}) {
		t.Fatalf("collected %v, want [no-status ok]", got)
	}
	q := env.mock.recorded(searchPath)[0].Query.Get("q")
	if !strings.Contains(q, ` AND event_score:>=40 AND tenantid:"tenantA" AND NOT event_status:"Ignored"`) {
		t.Errorf("q = %s", q)
	}
}

func TestCollectAlerts_ForeignCheckpointFallsBackToLookback(t *testing.T) {
	now := testBase
	lookbackStart := ms(now.Add(-7 * 24 * time.Hour))
	foreign := []string{
		"1793196390000", // QRadar epoch checkpoint
		checkpointJSON("cases", ms(now.Add(-time.Hour)), "case-1"),
		`{"v":2,"mode":"alerts","ts":1793196390000,"ids":[]}`,
		`{"v":1,"mode":"alerts","ts":0,"ids":[]}`,
		checkpointJSON("alerts", ms(now.Add(48*time.Hour))), // future
		"{not json",
	}
	for _, cp := range foreign {
		env := newSaaSEnv(t, nil)
		env.addAlerts(alertHit("x", ms(now.Add(-2*time.Hour)), 50))
		batch := mustCollect(t, env.coll, cp)
		if ms(batch.WindowFrom) != lookbackStart {
			t.Errorf("checkpoint %s: window starts at %v, want the lookback start", cp, batch.WindowFrom)
		}
		if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"x"}) {
			t.Errorf("checkpoint %s: collected %v", cp, got)
		}
	}

	// With nothing to collect the foreign checkpoint is replaced by a valid one.
	env := newSaaSEnv(t, nil)
	batch := mustCollect(t, env.coll, "1793196390000")
	if batch.Checkpoint != checkpointJSON("alerts", lookbackStart) {
		t.Errorf("checkpoint = %s, want a normalized alerts checkpoint", batch.Checkpoint)
	}
}

func TestCollectAlerts_DuplicatesAndOutOfWindowHits(t *testing.T) {
	env := newSaaSEnv(t, nil)
	ts := ms(env.clock.Now().Add(-time.Hour))
	dup := alertHit("dup", ts+1, 50)
	dup.Index = "another-index"
	env.addAlerts(alertHit("dup", ts, 50), dup, alertHit("other", ts+2, 50))
	batch := mustCollect(t, env.coll, "")
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"dup", "other"}) {
		t.Fatalf("collected %v", got)
	}
	if batch.Fetched != 3 || batch.DuplicatesRemoved != 1 {
		t.Errorf("fetched/dups = %d/%d, want 3/1", batch.Fetched, batch.DuplicatesRemoved)
	}
}

func TestCollectAlerts_SearchErrorFailsTheCycle(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.addAlerts(alertHit("x", ms(env.clock.Now().Add(-time.Hour)), 50))
	env.mock.failNext(searchPath, 500, "")
	if _, err := env.coll.Collect(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("err = %v", err)
	}
}

func TestCollect_CheckpointAtUpperBoundQueriesNothing(t *testing.T) {
	env := newSaaSEnv(t, nil)
	cp := checkpointJSON("alerts", ms(env.clock.Now().Add(-30*time.Second)), "x")
	batch := mustCollect(t, env.coll, cp)
	if batch.Checkpoint != cp || len(batch.Templates) != 0 {
		t.Errorf("batch = %+v", batch)
	}
	if n := len(env.mock.recorded(searchPath)); n != 0 {
		t.Errorf("search requests = %d, want 0", n)
	}
}

// --- cases mode -------------------------------------------------------------------

func casesEnv(t *testing.T, mutate func(*settings, *config.SyncConfig)) *testEnv {
	return newSaaSEnv(t, func(s *settings, sc *config.SyncConfig) {
		s.dataSource = dataSourceCases
		s.authMode, s.username, s.apiKey = authModeScopedKey, "", testScopedKey
		if mutate != nil {
			mutate(s, sc)
		}
	})
}

func docs(prefix string, n int, writeTime int64, score float64) []Hit {
	out := make([]Hit, n)
	for i := range out {
		out[i] = alertHit(fmt.Sprintf("%s-%03d", prefix, i), writeTime, score)
	}
	return out
}

func TestCollectCases_PerStatusQueriesAndAlertPaging(t *testing.T) {
	env := casesEnv(t, func(_ *settings, sc *config.SyncConfig) { sc.Filters.MinSeverity = "low" })
	now := env.clock.Now()
	t1, t2, t3, t4 := ms(now.Add(-4*time.Hour)), ms(now.Add(-3*time.Hour)), ms(now.Add(-2*time.Hour)), ms(now.Add(-time.Hour))

	c1Docs := docs("c1", 120, t1, 50)
	ignored := alertHit("c2-ignored", t2, 90)
	ignored.Source["event_status"] = "Ignored"
	noScore := alertHit("c2-noscore", t2, 0)
	delete(noScore.Source, "event_score")
	c2Docs := []Hit{c1Docs[5], ignored, alertHit("c2-low", t2, 10), noScore, alertHit("c2-ok", t2, 70)}

	env.addCases(
		mockCase{ID: "c1", Name: "Brute force", Status: "New", ModifiedAt: t1, Docs: c1Docs},
		mockCase{ID: "c2", Name: "Mixed", Status: "Resolved", ModifiedAt: t2, Docs: c2Docs},
		mockCase{ID: "c3", Name: "False positive", Status: "Cancelled", ModifiedAt: t3, Docs: docs("c3", 2, t3, 90)},
		mockCase{ID: "c4", Name: "Empty", Status: "In Progress", ModifiedAt: t4},
	)

	batch := mustCollect(t, env.coll, "")
	if len(batch.Templates) != 121 {
		t.Fatalf("collected %d alerts, want 120 from c1 + c2-ok", len(batch.Templates))
	}
	last := batch.Templates[len(batch.Templates)-1]
	if last.ExternalID != "c2-ok" || last.RawData["caseId"] != "c2" || last.RawData["caseName"] != "Mixed" {
		t.Errorf("last template = %+v", last)
	}
	if batch.Templates[0].RawData["caseId"] != "c1" || batch.Templates[0].RawData["caseName"] != "Brute force" {
		t.Errorf("first template rawData = %v", batch.Templates[0].RawData)
	}
	if batch.Fetched != 125 || batch.DuplicatesRemoved != 1 {
		t.Errorf("fetched/dups = %d/%d, want 125/1", batch.Fetched, batch.DuplicatesRemoved)
	}
	if batch.Checkpoint != checkpointJSON("cases", t4, "c4") {
		t.Errorf("checkpoint = %s", batch.Checkpoint)
	}

	lower, upper := ms(now.Add(-7*24*time.Hour)), ms(now.Add(-120*time.Second))
	var statuses []string
	for _, r := range env.mock.recorded(casesPath) {
		if r.Path != casesPath {
			continue
		}
		q := r.Query
		statuses = append(statuses, q.Get("status"))
		if q.Get("FROM~modified_at") != strconv.FormatInt(lower, 10) || q.Get("TO~modified_at") != strconv.FormatInt(upper, 10) ||
			q.Get("sort") != "modified_at" || q.Get("order") != "asc" || q.Get("limit") != "100" || q.Get("skip") != "0" || q.Has("tenantid") {
			t.Errorf("cases query = %v", q)
		}
	}
	if !reflect.DeepEqual(statuses, []string{"New", "In Progress", "Escalated", "Resolved"}) {
		t.Errorf("statuses queried = %v", statuses)
	}

	var c1Pages []string
	for _, r := range env.mock.recorded(casesPath + "/c1/alerts") {
		if r.Query.Get("limit") != "50" {
			t.Errorf("case alerts limit = %s", r.Query.Get("limit"))
		}
		c1Pages = append(c1Pages, r.Query.Get("skip"))
	}
	if !reflect.DeepEqual(c1Pages, []string{"0", "50", "100"}) {
		t.Errorf("c1 alert pages skip = %v, want [0 50 100]", c1Pages)
	}
}

func TestCollectCases_CasePagingAndTenant(t *testing.T) {
	env := casesEnv(t, func(s *settings, _ *config.SyncConfig) { s.tenantID = "tenantA" })
	base := ms(env.clock.Now().Add(-5 * time.Hour))
	for i := 0; i < 150; i++ {
		env.addCases(mockCase{ID: fmt.Sprintf("n%03d", i), Status: "New", TenantID: "tenantA", ModifiedAt: base + int64(i), Docs: docs(fmt.Sprintf("n%03d", i), 1, base, 50)})
	}
	env.addCases(mockCase{ID: "other-tenant", Status: "New", TenantID: "tenantB", ModifiedAt: base, Docs: docs("ot", 1, base, 50)})

	batch := mustCollect(t, env.coll, "")
	if len(batch.Templates) != 150 {
		t.Fatalf("collected %d, want 150", len(batch.Templates))
	}
	var newSkips []string
	for _, r := range env.mock.recorded(casesPath) {
		if r.Path != casesPath {
			continue
		}
		if r.Query.Get("tenantid") != "tenantA" {
			t.Errorf("tenantid = %q", r.Query.Get("tenantid"))
		}
		if r.Query.Get("status") == "New" {
			newSkips = append(newSkips, r.Query.Get("skip"))
		}
	}
	if !reflect.DeepEqual(newSkips, []string{"0", "100"}) {
		t.Errorf("New pages skip = %v, want [0 100]", newSkips)
	}
}

func TestCollectCases_CheckpointSkipAndCapNeverSplitsACase(t *testing.T) {
	env := casesEnv(t, func(_ *settings, sc *config.SyncConfig) { sc.MaxAlertsPerSync = 2 })
	base := ms(env.clock.Now().Add(-time.Hour))
	t1, t2, t3 := base, base+1000, base+2000
	env.addCases(
		mockCase{ID: "k1", Status: "New", ModifiedAt: t1, Docs: docs("k1", 1, t1, 50)},
		mockCase{ID: "k2", Status: "New", ModifiedAt: t2, Docs: docs("k2", 1, t2, 50)},
		mockCase{ID: "k3", Status: "Escalated", ModifiedAt: t2, Docs: docs("k3", 3, t2, 50)},
		mockCase{ID: "k4", Status: "Resolved", ModifiedAt: t3, Docs: docs("k4", 1, t3, 50)},
	)

	batch := mustCollect(t, env.coll, "")
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"k1-000", "k2-000"}) {
		t.Fatalf("first cycle %v", got)
	}
	if batch.Checkpoint != checkpointJSON("cases", t2, "k2") {
		t.Fatalf("checkpoint = %s", batch.Checkpoint)
	}

	batch = mustCollect(t, env.coll, batch.Checkpoint)
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"k3-000", "k3-001", "k3-002"}) {
		t.Fatalf("second cycle %v (k3 must not be split)", got)
	}
	if batch.Checkpoint != checkpointJSON("cases", t2, "k2", "k3") {
		t.Fatalf("checkpoint = %s", batch.Checkpoint)
	}

	batch = mustCollect(t, env.coll, batch.Checkpoint)
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"k4-000"}) {
		t.Fatalf("third cycle %v", got)
	}
}

func TestCollectCases_AlertsCheckpointIsForeign(t *testing.T) {
	env := casesEnv(t, nil)
	ts := ms(env.clock.Now().Add(-time.Hour))
	env.addCases(mockCase{ID: "k1", Status: "New", ModifiedAt: ts, Docs: docs("k1", 1, ts, 50)})
	batch := mustCollect(t, env.coll, checkpointJSON("alerts", ts+1, "x"))
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"k1-000"}) {
		t.Fatalf("collected %v, want the case found through the lookback window", got)
	}
}

// --- Init / config -------------------------------------------------------------------

func TestInit_ProbesTheDataSource(t *testing.T) {
	env := newSaaSEnv(t, nil)
	if err := env.coll.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(env.mock.recorded(searchPath)); n != 1 {
		t.Errorf("alerts probe requests = %d", n)
	}
	if n := len(env.mock.recorded(casesHealthAPI)); n != 1 {
		t.Errorf("health requests = %d", n)
	}
	if err := env.coll.HealthCheck(context.Background()); err != nil {
		t.Errorf("HealthCheck: %v", err)
	}

	env = casesEnv(t, nil)
	if err := env.coll.Init(context.Background()); err != nil {
		t.Fatal(err)
	}
	reqs := env.mock.recorded(casesPath)
	if len(reqs) == 0 || reqs[0].Path != casesPath || reqs[0].Query.Get("limit") != "1" {
		t.Errorf("cases probe = %+v", reqs)
	}
	if n := len(env.mock.recorded(searchPath)); n != 0 {
		t.Errorf("cases mode must not touch the alert index (%d requests)", n)
	}
	if err := env.coll.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func validStellarConfig() config.SIEMConfig {
	return config.SIEMConfig{
		Type:   Name,
		APIURL: "https://acme.stellarcyber.cloud",
		Credentials: config.CredentialConfig{
			Username: "api@acme.com",
			APIKey:   "token",
		},
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*config.SIEMConfig)
		wantErr string
	}{
		{"defaults are valid", func(*config.SIEMConfig) {}, ""},
		{"onprem over http", func(c *config.SIEMConfig) { c.Deployment, c.APIURL = "onprem", "http://10.0.0.5" }, ""},
		{"scoped key needs no username", func(c *config.SIEMConfig) { c.Credentials.AuthMode, c.Credentials.Username = "scoped_key", "" }, ""},
		{"saas requires https", func(c *config.SIEMConfig) { c.APIURL = "http://acme.stellarcyber.cloud" }, "must use https"},
		{"api_token requires username", func(c *config.SIEMConfig) { c.Credentials.Username = "" }, "username"},
		{"username must be an email", func(c *config.SIEMConfig) { c.Credentials.Username = "admin" }, "email"},
		{"bad deployment", func(c *config.SIEMConfig) { c.Deployment = "cloud" }, "siem.deployment"},
		{"bad data source", func(c *config.SIEMConfig) { c.DataSource = "incidents" }, "siem.data_source"},
		{"bad auth mode", func(c *config.SIEMConfig) { c.Credentials.AuthMode = "oauth" }, "auth_mode"},
		{"api key required", func(c *config.SIEMConfig) { c.Credentials.APIKey = " " }, "api_key"},
		{"api url required", func(c *config.SIEMConfig) { c.APIURL = "" }, "api_url"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validStellarConfig()
			tt.mutate(&cfg)
			err := ValidateConfig(cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestRegisteredInCollectorRegistry(t *testing.T) {
	if err := collector.ValidateConfig(validStellarConfig()); err != nil {
		t.Fatalf("registry validation: %v", err)
	}
	cfg := validStellarConfig()
	cfg.Deployment = "cloud"
	if err := collector.ValidateConfig(cfg); err == nil {
		t.Fatal("registry must run the Stellar Cyber validator")
	}
	coll, err := collector.New(validStellarConfig(), config.SyncConfig{MaxAlertsPerSync: 50000, Filters: config.Filters{MinSeverity: "high"}})
	if err != nil {
		t.Fatal(err)
	}
	sc := coll.(*Collector)
	if sc.Name() != "stellar_cyber" || sc.maxAlerts != 10000 || sc.minScore != 60 || sc.lookback != 7*24*time.Hour {
		t.Errorf("collector = name %s maxAlerts %d minScore %d lookback %v", sc.Name(), sc.maxAlerts, sc.minScore, sc.lookback)
	}
	if _, err := collector.New(validStellarConfig(), config.SyncConfig{Filters: config.Filters{MinSeverity: "severe"}}); err == nil {
		t.Error("an invalid min_severity must fail")
	}
}

// A failing factory must return an untyped nil Collector, not a nil
// *Collector wrapped in the interface (which compares != nil).
func TestNew_ErrorReturnsUntypedNil(t *testing.T) {
	cfg := validStellarConfig()
	cfg.Credentials.CACertFile = "/nonexistent/ca.pem"
	coll, err := collector.New(cfg, config.SyncConfig{})
	if err == nil || coll != nil {
		t.Fatalf("collector.New = %#v, %v; want nil and an error", coll, err)
	}
	coll, err = New(cfg, config.SyncConfig{})
	if err == nil || coll != nil {
		t.Fatalf("New = %#v, %v; want nil and an error", coll, err)
	}
}
