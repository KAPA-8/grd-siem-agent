package stellarcyber

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
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
	// Keyset paging: page 2 is anchored at d3's write_time, asks for the 2
	// alerts still wanted plus d3 (skipped by ID), and never uses from.
	var sizes, froms, lowers []string
	for _, r := range env.mock.recorded(searchPath) {
		sizes = append(sizes, r.Query.Get("size"))
		froms = append(froms, r.Query.Get("from"))
		lowers = append(lowers, strings.TrimPrefix(strings.Split(r.Query.Get("q"), " TO ")[0], "write_time:["))
	}
	lower := strconv.FormatInt(ms(env.clock.Now().Add(-7*24*time.Hour)), 10)
	if !reflect.DeepEqual(sizes, []string{"3", "3"}) || !reflect.DeepEqual(froms, []string{"0", "0"}) ||
		!reflect.DeepEqual(lowers, []string{lower, strconv.FormatInt(base+3, 10)}) {
		t.Errorf("pages size=%v from=%v write_time>=%v, want [3 3] [0 0] [%s %d]", sizes, froms, lowers, lower, base+3)
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

// A 10050-alert backlog with the 10000 cap: every request is anchored
// (from=0, size<=500), the cap holds and the rest continues next cycle.
func TestCollectAlerts_LargeBacklogWithTheMaximumCap(t *testing.T) {
	env := newSaaSEnv(t, func(_ *settings, sc *config.SyncConfig) { sc.MaxAlertsPerSync = 10000 })
	base := ms(env.clock.Now().Add(-48 * time.Hour))
	hits := make([]Hit, 10050)
	for i := range hits {
		hits[i] = alertHit(fmt.Sprintf("w%05d", i), base+int64(i)*1000, 50)
	}
	env.addAlerts(hits...)

	batch := mustCollect(t, env.coll, "")
	if len(batch.Templates) != 10000 || batch.Templates[9999].ExternalID != "w09999" {
		t.Fatalf("collected %d, want w00000..w09999", len(batch.Templates))
	}
	for _, r := range env.mock.recorded(searchPath) {
		from, _ := strconv.Atoi(r.Query.Get("from"))
		size, _ := strconv.Atoi(r.Query.Get("size"))
		if from != 0 || size > 500 {
			t.Fatalf("request from=%d size=%d, want anchored pages of at most 500", from, size)
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

// Keyset paging is not bound by the from+size window: with a window of 10
// and pages of 3, one cycle still collects all 25 alerts.
func TestCollectAlerts_KeysetPagingIsNotBoundByTheResultWindow(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.coll.pageSize, env.coll.maxResultWindow = 3, 10
	base := ms(env.clock.Now().Add(-time.Hour))
	var want []string
	for i := 0; i < 25; i++ {
		id := fmt.Sprintf("k%02d", i)
		want = append(want, id)
		env.addAlerts(alertHit(id, base+int64(i), 50))
	}
	batch := mustCollect(t, env.coll, "")
	if got := externalIDs(batch); !reflect.DeepEqual(got, want) {
		t.Fatalf("collected %v", got)
	}
	for _, r := range env.mock.recorded(searchPath) {
		if r.Query.Get("from") != "0" {
			t.Errorf("request from=%s, want 0", r.Query.Get("from"))
		}
	}
}

// More alerts in one millisecond than a page can skip past: that millisecond
// is paged by offset, and nothing is lost.
func TestCollectAlerts_LargeTieGroupIsPagedByOffset(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.coll.pageSize = 2
	ts := ms(env.clock.Now().Add(-time.Hour))
	for i := 1; i <= 5; i++ {
		env.addAlerts(alertHit("s"+strconv.Itoa(i), ts, 50))
	}
	env.addAlerts(alertHit("later", ts+1, 50))

	batch := mustCollect(t, env.coll, "")
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"s1", "s2", "s3", "s4", "s5", "later"}) {
		t.Fatalf("collected %v", got)
	}
	var froms []string
	for _, r := range env.mock.recorded(searchPath) {
		froms = append(froms, r.Query.Get("from"))
	}
	if !reflect.DeepEqual(froms, []string{"0", "2", "4", "0"}) {
		t.Errorf("froms = %v, want [0 2 4 0]", froms)
	}
}

// Offset pages inside a big tie group whose order changes on every request
// may return only alerts already read: the offset moves on, the cycle does
// not fail, and later write_times are still reached.
func TestCollectAlerts_ReorderedLargeTieGroupDoesNotFailTheCycle(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.coll.pageSize = 3
	env.mock.shuffleTies = true
	ts := ms(env.clock.Now().Add(-time.Hour))
	for i := 0; i < 30; i++ {
		env.addAlerts(alertHit(fmt.Sprintf("t%02d", i), ts, 50))
	}
	env.addAlerts(alertHit("after", ts+1, 50))
	for run := 0; run < 20; run++ {
		env.mock.resetRequests()
		batch := mustCollect(t, env.coll, "")
		ids := externalIDs(batch)
		if len(ids) == 0 || ids[len(ids)-1] != "after" {
			t.Fatalf("run %d: collected %v, want the tie group then \"after\"", run, ids)
		}
	}
}

// When every reachable result was already delivered at the checkpoint ts,
// the collector steps past that millisecond instead of stalling forever.
func TestCollectAlerts_WindowExhaustedAtCheckpointTimestamp(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.coll.pageSize, env.coll.maxResultWindow = 2, 4
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

// Regression (review P2): an alert on page 1 is marked Ignored while page 2
// is being requested. With from/size offsets every later alert shifted one
// place left and a0500 was never collected; anchored pages lose nothing.
func TestCollectAlerts_AlertLeavingTheResultSetWhilePagingIsNotLost(t *testing.T) {
	env := newSaaSEnv(t, nil)
	var once sync.Once
	searches := 0
	env.mock.onRequest = func(m *mockStellar, r *http.Request) {
		if r.URL.Path != searchPath {
			return
		}
		if searches++; searches == 2 {
			once.Do(func() {
				m.mu.Lock()
				m.alerts[10].Source["event_status"] = "Ignored"
				m.mu.Unlock()
			})
		}
	}
	base := ms(env.clock.Now().Add(-time.Hour))
	for i := 0; i < 800; i++ {
		env.addAlerts(alertHit(fmt.Sprintf("a%04d", i), base+int64(i), 50))
	}

	batch := mustCollect(t, env.coll, "")
	got := externalIDs(batch)
	if len(got) != 800 {
		missing := []string{}
		seen := map[string]bool{}
		for _, id := range got {
			seen[id] = true
		}
		for i := 0; i < 800; i++ {
			if id := fmt.Sprintf("a%04d", i); !seen[id] {
				missing = append(missing, id)
			}
		}
		t.Fatalf("collected %d alerts, missing %v", len(got), missing)
	}
	if cp := decodeCheckpoint(t, batch.Checkpoint); cp.TS != base+799 {
		t.Errorf("checkpoint = %+v", cp)
	}
}

// Elasticsearch may return alerts that share a write_time in a different
// order on every request. Page boundaries fall inside the tie groups, and
// across pages and capped cycles every alert is still delivered exactly once.
func TestCollectAlerts_TieOrderVaryingBetweenPagesLosesNothing(t *testing.T) {
	env := newSaaSEnv(t, func(_ *settings, sc *config.SyncConfig) { sc.MaxAlertsPerSync = 7 })
	env.coll.pageSize = 5
	env.mock.shuffleTies = true
	base := ms(env.clock.Now().Add(-time.Hour))
	for g := 0; g < 10; g++ {
		for i := 0; i < 4; i++ {
			env.addAlerts(alertHit(fmt.Sprintf("g%d-%02d", g, i), base+int64(g)*1000, 50))
		}
	}

	delivered := map[string]int{}
	cp := ""
	for cycle := 0; cycle < 20; cycle++ {
		batch := mustCollect(t, env.coll, cp)
		for _, id := range externalIDs(batch) {
			delivered[id]++
		}
		if len(batch.Templates) == 0 {
			break
		}
		cp = batch.Checkpoint
	}
	if len(delivered) != 40 {
		t.Fatalf("delivered %d distinct alerts, want 40", len(delivered))
	}
	if len(env.mock.recorded(searchPath)) < 10 {
		t.Errorf("only %d searches: the tie groups did not straddle pages", len(env.mock.recorded(searchPath)))
	}
	for id, n := range delivered {
		if n != 1 {
			t.Errorf("%s delivered %d times", id, n)
		}
	}
}

// Keyset paging needs the server to sort by write_time; unsorted results
// fail the cycle (checkpoint kept) instead of silently losing alerts.
func TestCollectAlerts_UnsortedResultsFailTheCycle(t *testing.T) {
	env := newSaaSEnv(t, nil)
	env.mock.ignoreSort = true
	base := ms(env.clock.Now().Add(-time.Hour))
	for i := 5; i > 0; i-- {
		env.addAlerts(alertHit("u"+strconv.Itoa(i), base+int64(i), 50))
	}
	_, err := env.coll.Collect(context.Background(), "")
	if err == nil || !strings.Contains(err.Error(), "not sorted by write_time") {
		t.Fatalf("err = %v, want a not-sorted error", err)
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
	// Keyset paging: page 2 is anchored at n099's modified_at and asks for
	// a full page plus n099 itself.
	var newPages [][3]string
	for _, r := range env.mock.recorded(casesPath) {
		if r.Path != casesPath {
			continue
		}
		if r.Query.Get("tenantid") != "tenantA" {
			t.Errorf("tenantid = %q", r.Query.Get("tenantid"))
		}
		if r.Query.Get("status") == "New" {
			newPages = append(newPages, [3]string{r.Query.Get("FROM~modified_at"), r.Query.Get("skip"), r.Query.Get("limit")})
		}
	}
	lower := strconv.FormatInt(ms(env.clock.Now().Add(-7*24*time.Hour)), 10)
	want := [][3]string{{lower, "0", "100"}, {strconv.FormatInt(base+99, 10), "0", "101"}}
	if !reflect.DeepEqual(newPages, want) {
		t.Errorf("New pages (FROM~, skip, limit) = %v, want %v", newPages, want)
	}
}

// Regression (review P2): a page-1 case is modified (its modified_at jumps
// past the window) while page 2 is being requested. With skip offsets the
// later cases shifted one place left and n100 was never collected, while
// the checkpoint moved past it; anchored pages lose nothing.
func TestCollectCases_CaseModifiedWhileListingIsNotLost(t *testing.T) {
	env := casesEnv(t, nil)
	newListings := 0
	env.mock.onRequest = func(m *mockStellar, r *http.Request) {
		if r.URL.Path != casesPath || r.URL.Query().Get("status") != "New" {
			return
		}
		if newListings++; newListings == 2 {
			m.mu.Lock()
			for i := range m.cases {
				if m.cases[i].ID == "n010" { // an analyst updates n010 right now
					m.cases[i].ModifiedAt = m.clock.Now().UnixMilli()
				}
			}
			m.mu.Unlock()
		}
	}
	base := ms(env.clock.Now().Add(-5 * time.Hour))
	for i := 0; i < 150; i++ {
		id := fmt.Sprintf("n%03d", i)
		env.addCases(mockCase{ID: id, Status: "New", ModifiedAt: base + int64(i), Docs: docs(id, 1, base, 50)})
	}

	batch := mustCollect(t, env.coll, "")
	if len(batch.Templates) != 150 {
		t.Fatalf("first cycle collected %d alerts, want all 150", len(batch.Templates))
	}
	if cp := decodeCheckpoint(t, batch.Checkpoint); cp.TS != base+149 || !reflect.DeepEqual(cp.IDs, []string{"n149"}) {
		t.Errorf("checkpoint = %+v", cp)
	}
	// n010 is collected again once its new modified_at is inside the window.
	env.clock.Advance(15 * time.Minute)
	batch = mustCollect(t, env.coll, batch.Checkpoint)
	if got := externalIDs(batch); !reflect.DeepEqual(got, []string{"n010-000"}) {
		t.Errorf("second cycle collected %v, want the modified n010", got)
	}
}

// Cases sharing a modified_at come back in a different order on every
// request: every case is still listed exactly once.
func TestCollectCases_TieOrderVaryingBetweenPagesLosesNothing(t *testing.T) {
	env := casesEnv(t, nil)
	env.coll.casesPageSize = 20
	env.mock.shuffleTies = true
	base := ms(env.clock.Now().Add(-time.Hour))
	for g := 0; g < 5; g++ {
		for i := 0; i < 50; i++ {
			id := fmt.Sprintf("g%d-%02d", g, i)
			env.addCases(mockCase{ID: id, Status: "Escalated", ModifiedAt: base + int64(g)*1000, Docs: docs(id, 1, base, 50)})
		}
	}
	batch := mustCollect(t, env.coll, "")
	counts := map[string]int{}
	for _, id := range externalIDs(batch) {
		counts[id]++
	}
	if len(counts) != 250 || len(batch.Templates) != 250 {
		t.Fatalf("collected %d alerts (%d distinct), want 250", len(batch.Templates), len(counts))
	}
}

// More cases in one millisecond than one request may return on top of a
// page: that millisecond is paged by skip, and nothing is lost.
func TestCollectCases_LargeTieGroupIsPagedBySkip(t *testing.T) {
	env := casesEnv(t, nil)
	env.coll.casesPageSize, env.coll.maxCasesLimit = 3, 5
	ts := ms(env.clock.Now().Add(-time.Hour))
	for i := 1; i <= 8; i++ {
		id := fmt.Sprintf("t%d", i)
		env.addCases(mockCase{ID: id, Status: "New", ModifiedAt: ts, Docs: docs(id, 1, ts, 50)})
	}
	env.addCases(
		mockCase{ID: "later1", Status: "New", ModifiedAt: ts + 1, Docs: docs("later1", 1, ts, 50)},
		mockCase{ID: "later2", Status: "New", ModifiedAt: ts + 2, Docs: docs("later2", 1, ts, 50)},
	)
	batch := mustCollect(t, env.coll, "")
	if len(batch.Templates) != 10 {
		t.Fatalf("collected %v, want 10 alerts", externalIDs(batch))
	}
	var pages [][2]string
	for _, r := range env.mock.recorded(casesPath) {
		if r.Path == casesPath && r.Query.Get("status") == "New" {
			pages = append(pages, [2]string{r.Query.Get("skip"), r.Query.Get("limit")})
		}
	}
	want := [][2]string{{"0", "3"}, {"3", "3"}, {"6", "3"}, {"0", "4"}}
	if !reflect.DeepEqual(pages, want) {
		t.Errorf("New pages (skip, limit) = %v, want %v", pages, want)
	}
}

// A server that ignores sort=modified_at gets the offset listing (the cases
// are sorted locally), so cases mode keeps working.
func TestCollectCases_UnsortedListingFallsBackToSkip(t *testing.T) {
	env := casesEnv(t, nil)
	env.mock.ignoreSort = true
	base := ms(env.clock.Now().Add(-5 * time.Hour))
	for i := 149; i >= 0; i-- {
		id := fmt.Sprintf("r%03d", i)
		env.addCases(mockCase{ID: id, Status: "New", ModifiedAt: base + int64(i), Docs: docs(id, 1, base, 50)})
	}
	batch := mustCollect(t, env.coll, "")
	if got := externalIDs(batch); len(got) != 150 || got[0] != "r000-000" || got[149] != "r149-000" {
		t.Fatalf("collected %d alerts (%v ... )", len(got), got[:min(3, len(got))])
	}
	var skips []string
	for _, r := range env.mock.recorded(casesPath) {
		if r.Path == casesPath && r.Query.Get("status") == "New" {
			skips = append(skips, r.Query.Get("skip"))
		}
	}
	if !reflect.DeepEqual(skips, []string{"0", "0", "100"}) {
		t.Errorf("New pages skip = %v, want the keyset attempt then [0 100]", skips)
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
