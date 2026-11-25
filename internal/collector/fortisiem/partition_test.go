package fortisiem

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/config"
)

// tiedIncidents adds n incidents last seen in groups of perSecond within the
// same second, ending one second before now (the shape that makes
// FortiSIEM's paging unstable: many incidents share incidentLastSeen).
func tiedIncidents(env *testEnv, firstID int64, n, perSecond int) []int64 {
	var ids []int64
	for i := range n {
		at := testBase.Add(-time.Duration(n/perSecond-i/perSecond) * time.Second)
		id := firstID + int64(i)
		env.mock.add(securityIncident(id, at))
		ids = append(ids, id)
	}
	return ids
}

// naiveRead pages [from, to] with start/size as the collector did before the
// partition, and counts how often each incidentId came back.
func naiveRead(t *testing.T, env *testEnv, from, to int64) map[string]int {
	t.Helper()
	counts := map[string]int{}
	size := env.coll.pageSize
	for start := 0; ; start += size {
		pg, err := env.coll.query(context.Background(), start, size, from, to)
		if err != nil {
			t.Fatal(err)
		}
		if pg.Items == 0 {
			break
		}
		for _, inc := range pg.Data {
			counts[incidentID(inc["incidentId"])]++
		}
		if pg.HasTotal && int64(start+size) >= pg.Total {
			break
		}
	}
	return counts
}

func checkOnce(t *testing.T, label string, got []string, want []int64) {
	t.Helper()
	seen := map[string]int{}
	for _, id := range got {
		seen[id]++
	}
	missing, repeated := 0, 0
	for _, id := range idsOf(want...) {
		if seen[id] == 0 {
			missing++
		}
	}
	for _, n := range seen {
		if n > 1 {
			repeated++
		}
	}
	if missing > 0 || repeated > 0 || len(seen) != len(want) {
		t.Errorf("%s: %d missing, %d repeated, %d distinct of %d", label, missing, repeated, len(seen), len(want))
	}
}

// Regression test of the defect measured on FortiSIEM Cloud: with unstable
// paging, a start/size read of the window loses incidents, and the window
// partition gets all of them, in the incremental pass and in the sweep.
func TestPartition_UnstablePagingRegression(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 10000 })
		env.coll.pageSize = 100
		env.mock.inclusiveEnd = true
		env.mock.setUnstable(7, 3)
		want := tiedIncidents(env, 1000, 3000, 10)

		from, to := ms(testBase.Add(-7*24*time.Hour)), ms(testBase)
		counts := naiveRead(t, env, from, to)
		missing := 0
		for _, id := range idsOf(want...) {
			if counts[id] == 0 {
				missing++
			}
		}
		if missing == 0 {
			t.Fatal("the unstable mock did not reproduce the defect: start/size paging found every incident")
		}
		t.Logf("start/size paging: %d of %d incidents missing", missing, len(want))

		env.mock.resetRequests()
		ids, b := env.collect(t, "")
		checkOnce(t, "partition", ids, want)
		for i, r := range env.mock.recorded(incidentPath) {
			if r.Query.Start != 0 {
				t.Fatalf("query %d paged (start=%d) a window that could be split", i, r.Query.Start)
			}
		}

		// The status sweep reads the lookback window the same way.
		env.clock.Advance(6 * time.Hour)
		ids, _ = env.collect(t, b.checkpoint)
		checkOnce(t, "sweep", ids, want)
	})
}

// More than a page of incidents last seen in the same second cannot be split:
// it is paged by incidentId and read again until the union holds total
// incidents (or two reads in a row add none).
func TestPartition_DenseSecondIsReadUntilStable(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 10000 })
		env.coll.pageSize = 100
		env.mock.inclusiveEnd = true
		env.mock.setUnstable(11, 2)
		want := tiedIncidents(env, 5000, 350, 350)               // one second
		want = append(want, tiedIncidents(env, 9000, 400, 4)...) // and a spread-out tail
		ids, _ := env.collect(t, "")
		checkOnce(t, "dense", ids, want)

		paged := 0
		for _, r := range env.mock.recorded(incidentPath) {
			if r.Query.Start > 0 {
				paged++
				if r.Query.OrderBy != orderByIncidentID || r.Query.TimeTo-r.Query.TimeFrom >= minSplitWindow {
					t.Errorf("paged query %+v, want orderBy incidentId within one short window", r.Query)
				}
			}
		}
		if paged < 3 { // at least one full read of four pages (start 100, 200, 300)
			t.Errorf("paged queries = %d, want a full read", paged)
		}
	})
}

func TestPartition_DenseFallsBackWhenOrderByIncidentIDIsRejected(t *testing.T) {
	env := newEnv(t, profile74, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 10000 })
	env.coll.pageSize = 100
	env.mock.rejectOrderByIncidentID = true
	want := tiedIncidents(env, 5000, 250, 250)
	ids, _ := env.collect(t, "")
	checkOnce(t, "dense without orderBy incidentId", ids, want)
	if env.coll.denseOrderBy != orderByLastSeen {
		t.Errorf("denseOrderBy = %s", env.coll.denseOrderBy)
	}
}

// A server that caps its pages below the size asked for sets the real
// capacity: the window is split by it, never paged.
func TestPartition_ServerCapsPages(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 10000 })
		env.coll.pageSize = 100
		env.mock.maxPage = 60
		want := tiedIncidents(env, 1000, 300, 4)
		ids, _ := env.collect(t, "")
		checkOnce(t, "capped pages", ids, want)
		for i, r := range env.mock.recorded(incidentPath) {
			if r.Query.Start != 0 {
				t.Fatalf("query %d paged (start=%d)", i, r.Query.Start)
			}
		}
	})
}

// Without total a full page means "maybe more": the window is split until
// every subwindow comes back shorter than a page.
func TestPartition_WithoutTotal(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 10000 })
		env.coll.pageSize = 100
		env.mock.omitTotal = true
		env.mock.setUnstable(5, 3)
		want := tiedIncidents(env, 1000, 1000, 5)
		ids, _ := env.collect(t, "")
		checkOnce(t, "without total", ids, want)
		for i, r := range env.mock.recorded(incidentPath) {
			if r.Query.Start != 0 {
				t.Fatalf("query %d paged (start=%d)", i, r.Query.Start)
			}
		}
	})
}

// A dense window whose total never matches (the server counts more than it
// returns) stops after two reads in a row add nothing: three reads.
func TestPartition_DenseStopsAfterTwoQuietReads(t *testing.T) {
	env := newEnv(t, profileCloud, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 10000 })
	env.coll.pageSize = 100
	env.mock.totalAdjust = func(q incidentQuery, total int) int {
		if q.TimeTo-q.TimeFrom < minSplitWindow && total > 100 {
			return total + 50
		}
		return total
	}
	want := tiedIncidents(env, 5000, 250, 250)
	ids, _ := env.collect(t, "")
	checkOnce(t, "dense, inconsistent total", ids, want)
	reads := 0
	for _, r := range env.mock.recorded(incidentPath) {
		if r.Query.OrderBy == orderByIncidentID && r.Query.Start == 0 {
			reads++
		}
	}
	if reads != 3 {
		t.Errorf("dense reads = %d, want 3 (one that adds, two that add nothing)", reads)
	}
}

// incidentLastSeen only grows: an incident that moves while the window is
// being read lands in a subwindow not read yet, and one read before it moved
// is not delivered twice.
func TestPartition_IncidentMovedDuringTheScan(t *testing.T) {
	bothProfiles(t, func(t *testing.T, profile mockProfile) {
		env := newEnv(t, profile, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 10000 })
		env.coll.pageSize = 100
		var want []int64
		for i := int64(0); i < 1000; i++ {
			env.mock.add(securityIncident(i+1, testBase.Add(-time.Duration(1000-i)*time.Minute)))
			want = append(want, i+1)
		}
		env.mock.onQuery = func(n int) {
			if n == 6 { // a few subwindows in
				env.mock.update(2, func(inc *mockIncident) { inc.LastSeen = ms(testBase) })   // read already
				env.mock.update(900, func(inc *mockIncident) { inc.LastSeen = ms(testBase) }) // not read yet
			}
		}
		ids, _ := env.collect(t, "")
		checkOnce(t, "moved", ids, want)
	})
}

func TestPartition_TruncationStopsQuerying(t *testing.T) {
	fill := func(env *testEnv) {
		env.coll.pageSize = 100
		for i := int64(0); i < 2000; i++ {
			env.mock.add(securityIncident(i+1, testBase.Add(-time.Duration(2000-i)*time.Minute)))
		}
	}
	full := newEnv(t, profileCloud, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 10000 })
	fill(full)
	full.collect(t, "")
	fullQueries := len(full.mock.recorded(incidentPath))

	env := newEnv(t, profileCloud, func(_ *settings, s *config.SyncConfig) { s.MaxAlertsPerSync = 50; s.StatusRefreshHours = 0 })
	fill(env)
	var all []string
	checkpoint := ""
	for cycle := 0; cycle < 2; cycle++ {
		env.mock.resetRequests()
		ids, b := env.collect(t, checkpoint)
		if len(ids) != 50 {
			t.Fatalf("cycle %d: %d templates, want 50", cycle, len(ids))
		}
		if n := len(env.mock.recorded(incidentPath)); n >= fullQueries/2 {
			t.Errorf("cycle %d: %d queries to fill 50 alerts, %d to read everything", cycle, n, fullQueries)
		}
		all = append(all, ids...)
		checkpoint = b.checkpoint
	}
	if strings.Join(all, ",") != strings.Join(idsOf(func() []int64 {
		var out []int64
		for i := int64(1); i <= 100; i++ {
			out = append(out, i)
		}
		return out
	}()...), ",") {
		t.Errorf("two truncated cycles delivered %v..., want the 100 oldest in order", all[:5])
	}
}

func TestPartition_RequestLimit(t *testing.T) {
	env := newEnv(t, profileCloud, nil)
	env.coll.pageSize = 100
	env.coll.maxRequests = 3
	tiedIncidents(env, 1, 1000, 1)
	batch, err := env.coll.Collect(context.Background(), "")
	if !errors.Is(err, errRequestLimit) || !strings.Contains(err.Error(), "sync.lookback_days") {
		t.Fatalf("err = %v", err)
	}
	if batch.Checkpoint != "" || len(batch.Templates) != 0 {
		t.Errorf("a failed collection returned a batch: %+v", batch)
	}
	if n := len(env.mock.recorded(incidentPath)); n != 3 {
		t.Errorf("queries = %d, want the limit (3)", n)
	}
	// The budget is per collection.
	env.coll.maxRequests = 1000
	if _, err := env.coll.Collect(context.Background(), ""); err != nil {
		t.Errorf("next collection: %v", err)
	}
}

func TestPartition_Cancellation(t *testing.T) {
	env := newEnv(t, profileCloud, nil)
	env.coll.pageSize = 100
	tiedIncidents(env, 1, 1000, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env.mock.onQuery = func(n int) {
		if n == 2 {
			cancel()
		}
	}
	if _, err := env.coll.Collect(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if n := len(env.mock.recorded(incidentPath)); n > 3 {
		t.Errorf("queries after the cancellation: %d", n)
	}
}

func TestLessID(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{{"9", "10", true}, {"10", "9", false}, {"100", "101", true}, {"abc", "abd", true}, {"9", "9", false}} {
		if got := lessID(c.a, c.b); got != c.want {
			t.Errorf("lessID(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
