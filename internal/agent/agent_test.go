package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"

	"github.com/grd-platform/grd-siem-agent/internal/buffer"
	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/config"
	"github.com/grd-platform/grd-siem-agent/internal/health"
	"github.com/grd-platform/grd-siem-agent/internal/models"
	"github.com/grd-platform/grd-siem-agent/internal/transport"
)

// --- fakes -------------------------------------------------------------------------

type collectResult struct {
	batch collector.Batch
	err   error
}

// fakeCollector returns scripted results; once exhausted it returns an empty
// batch with the checkpoint it was given.
type fakeCollector struct {
	mu          sync.Mutex
	results     []collectResult
	checkpoints []string
	initErrs    []error
	initCalls   int
	healthErr   error
	healthCalls int
	closed      bool
}

func (f *fakeCollector) Name() string { return "fake" }

func (f *fakeCollector) Init(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.initCalls++
	if len(f.initErrs) > 0 {
		err := f.initErrs[0]
		f.initErrs = f.initErrs[1:]
		return err
	}
	return nil
}

func (f *fakeCollector) Collect(_ context.Context, checkpoint string) (collector.Batch, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.checkpoints = append(f.checkpoints, checkpoint)
	if len(f.results) == 0 {
		return collector.Batch{Checkpoint: checkpoint}, nil
	}
	r := f.results[0]
	f.results = f.results[1:]
	return r.batch, r.err
}

func (f *fakeCollector) HealthCheck(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.healthCalls++
	return f.healthErr
}

func (f *fakeCollector) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeCollector) push(batch collector.Batch, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.results = append(f.results, collectResult{batch, err})
}

// fakePlatform records sync payloads and answers through respond.
type fakePlatform struct {
	mu         sync.Mutex
	syncs      []models.SyncPayload
	heartbeats []models.HeartbeatPayload
	respond    func(call int, p models.SyncPayload) (*models.SyncResponse, error)
	hbErr      error
}

func okResponse(p models.SyncPayload) *models.SyncResponse {
	return &models.SyncResponse{Success: true, AlertsImported: len(p.Alerts)}
}

func (f *fakePlatform) SendSync(_ context.Context, p models.SyncPayload) (*models.SyncResponse, error) {
	f.mu.Lock()
	call := len(f.syncs)
	f.syncs = append(f.syncs, p)
	respond := f.respond
	f.mu.Unlock()
	if respond == nil {
		return okResponse(p), nil
	}
	return respond(call, p)
}

func (f *fakePlatform) SendHeartbeat(_ context.Context, p models.HeartbeatPayload) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats = append(f.heartbeats, p)
	return f.hbErr
}

func (f *fakePlatform) sent() []models.SyncPayload {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]models.SyncPayload(nil), f.syncs...)
}

// --- helpers -------------------------------------------------------------------------

const testConnectionID = "3f6c1d2e-8a4b-4c5d-9e6f-7a8b9c0d1e2f"

var (
	windowFrom = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	windowTo   = time.Date(2026, 10, 30, 11, 58, 0, 0, time.UTC)
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	return &config.Config{
		Agent:     config.AgentConfig{ID: "agent-1", Name: "test"},
		Platform:  config.PlatformConfig{URL: "https://grd.example.com", AgentToken: "grd_agent_x"},
		SIEM:      config.SIEMConfig{Type: "stellar_cyber", ConnectionID: testConnectionID},
		Sync:      config.SyncConfig{IntervalMinutes: 15, LookbackDays: 7, MaxAlertsPerSync: 1000},
		Buffer:    config.BufferConfig{Enabled: true, Path: filepath.Join(t.TempDir(), "buffer.db")},
		Heartbeat: config.HeartbeatConfig{IntervalSeconds: 60},
	}
}

func newTestAgent(t *testing.T, coll *fakeCollector, platform *fakePlatform, buf buffer.Buffer) *Agent {
	t.Helper()
	if buf == nil {
		buf = buffer.NewMemoryBuffer()
	}
	a := newAgent(testConfig(t), coll, platform, buf)
	a.retryCfg = transport.RetryConfig{InitialInterval: time.Millisecond, MaxInterval: 2 * time.Millisecond, MaxElapsedTime: 30 * time.Millisecond}
	return a
}

// fakeClock is a simulated transport.Clock: its timers fire at once and move
// the time forward by the wait, so the real /sync retry window (minutes) runs
// instantly.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func (c *fakeClock) NewTimer() backoff.Timer {
	return &fakeTimer{clock: c, c: make(chan time.Time, 1)}
}

type fakeTimer struct {
	clock *fakeClock
	c     chan time.Time
}

func (t *fakeTimer) Start(d time.Duration) {
	t.clock.Advance(d)
	t.c <- t.clock.Now()
}

func (t *fakeTimer) Stop()               {}
func (t *fakeTimer) C() <-chan time.Time { return t.c }

// newOutageAgent wires an agent with the production /sync retry policy on a
// simulated clock.
func newOutageAgent(t *testing.T, coll *fakeCollector, platform *fakePlatform, buf buffer.Buffer) (*Agent, *fakeClock) {
	t.Helper()
	a := newAgent(testConfig(t), coll, platform, buf)
	clock := newFakeClock()
	a.retryCfg.Clock = clock
	a.status.SetInit(nil)
	a.healthEvery = time.Hour
	return a, clock
}

var errPlatformDown = errors.New("sending sync: dial tcp 127.0.0.1:39999: connect: connection refused")

func templates(prefix string, n int) []models.AlertImportTemplate {
	out := make([]models.AlertImportTemplate, n)
	for i := range out {
		out[i] = models.AlertImportTemplate{
			ExternalID:  fmt.Sprintf("%s-%04d", prefix, i),
			TechniqueID: "T1110",
			Description: "alert",
			AlertDate:   "2026-10-29",
			Severity:    "high",
		}
	}
	return out
}

func batchOf(n int, checkpoint string) collector.Batch {
	return collector.Batch{
		Templates:  templates("a", n),
		Checkpoint: checkpoint,
		WindowFrom: windowFrom,
		WindowTo:   windowTo,
		Fetched:    n,
	}
}

func savedCheckpoint(t *testing.T, a *Agent) (string, bool) {
	t.Helper()
	data, err := os.ReadFile(a.checkpoints.path)
	if errors.Is(err, os.ErrNotExist) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(data), true
}

func bufLen(t *testing.T, b buffer.Buffer) int {
	t.Helper()
	n, err := b.Len()
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// --- collectAndSend ---------------------------------------------------------------------

func TestCollectAndSend_CheckpointAdvancesOnlyOnFullSuccess(t *testing.T) {
	tests := []struct {
		name     string
		respond  func(int, models.SyncPayload) (*models.SyncResponse, error)
		advanced bool
		buffered int
	}{
		{"success", nil, true, 0},
		{"limit reached still advances", func(_ int, p models.SyncPayload) (*models.SyncResponse, error) {
			return &models.SyncResponse{Success: true, AlertsImported: 1, AlertsSkipped: len(p.Alerts) - 1, LimitReached: true}, nil
		}, true, 0},
		{"insert errors", func(_ int, p models.SyncPayload) (*models.SyncResponse, error) {
			return &models.SyncResponse{Success: true, AlertsImported: len(p.Alerts) - 1, AlertsErrors: 1}, nil
		}, false, 0},
		{"permanently rejected alerts still advance", func(_ int, p models.SyncPayload) (*models.SyncResponse, error) {
			return &models.SyncResponse{Success: true, AlertsImported: len(p.Alerts) - 1, AlertsRejected: 1}, nil
		}, true, 0},
		{"success false", func(int, models.SyncPayload) (*models.SyncResponse, error) {
			return &models.SyncResponse{Success: false}, nil
		}, false, 0},
		{"platform down", func(int, models.SyncPayload) (*models.SyncResponse, error) {
			return nil, &transport.HTTPError{Op: "sync", StatusCode: 503, Body: "down"}
		}, false, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coll := &fakeCollector{}
			coll.push(batchOf(3, "cp-2"), nil)
			platform := &fakePlatform{respond: tt.respond}
			a := newTestAgent(t, coll, platform, nil)
			a.checkpoint = "cp-1"

			a.collectAndSend(context.Background(), nil)

			saved, ok := savedCheckpoint(t, a)
			if tt.advanced {
				if !ok || saved != "cp-2" || a.checkpoint != "cp-2" {
					t.Errorf("checkpoint not advanced: saved=%q (%v) memory=%q", saved, ok, a.checkpoint)
				}
			} else if ok || a.checkpoint != "cp-1" {
				t.Errorf("checkpoint advanced: saved=%q (%v) memory=%q", saved, ok, a.checkpoint)
			}
			if got := bufLen(t, a.buf); got != tt.buffered {
				t.Errorf("buffered = %d, want %d", got, tt.buffered)
			}
		})
	}
}

func TestCollectAndSend_ClientErrorsAreNotRetried(t *testing.T) {
	tests := []struct {
		status    int
		permanent bool
	}{
		{400, true}, {401, true}, {403, true}, {404, true}, {413, true}, {422, true},
		{408, false}, {429, false}, {500, false}, {502, false}, {503, false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprint(tt.status), func(t *testing.T) {
			coll := &fakeCollector{}
			coll.push(batchOf(2, "cp-2"), nil)
			platform := &fakePlatform{respond: func(int, models.SyncPayload) (*models.SyncResponse, error) {
				return nil, &transport.HTTPError{Op: "sync", StatusCode: tt.status, Body: "nope"}
			}}
			a := newTestAgent(t, coll, platform, nil)
			a.collectAndSend(context.Background(), nil)

			calls := len(platform.sent())
			if tt.permanent && calls != 1 {
				t.Errorf("status %d: %d attempts, want exactly 1", tt.status, calls)
			}
			if !tt.permanent && calls < 2 {
				t.Errorf("status %d: %d attempts, want retries", tt.status, calls)
			}
			if a.checkpoint != "" {
				t.Errorf("checkpoint advanced to %q", a.checkpoint)
			}
		})
	}
}

func TestCollectAndSend_ChunksOf500WithExactCounts(t *testing.T) {
	coll := &fakeCollector{}
	batch := batchOf(1201, "cp-2")
	batch.Fetched = 1210 // 4 duplicates + 5 dropped by filters/mapping
	batch.DuplicatesRemoved = 4
	coll.push(batch, nil)
	platform := &fakePlatform{}
	a := newTestAgent(t, coll, platform, nil)

	a.collectAndSend(context.Background(), nil)

	sent := platform.sent()
	if len(sent) != 3 {
		t.Fatalf("POSTs = %d, want 3", len(sent))
	}
	wantSizes := []int{500, 500, 201}
	totalFetched, totalAfter, totalDups := 0, 0, 0
	var ids []string
	for i, p := range sent {
		if len(p.Alerts) != wantSizes[i] {
			t.Errorf("chunk %d has %d alerts, want %d", i, len(p.Alerts), wantSizes[i])
		}
		if p.ConnectionID != testConnectionID || p.SyncMetadata.SIEMType != "stellar_cyber" || p.SyncMetadata.AgentVersion == "" {
			t.Errorf("chunk %d envelope = %+v", i, p.SyncMetadata)
		}
		if p.SyncMetadata.TotalAfterFilter != len(p.Alerts) {
			t.Errorf("chunk %d total_after_filter = %d", i, p.SyncMetadata.TotalAfterFilter)
		}
		totalFetched += p.SyncMetadata.TotalFetched
		totalAfter += p.SyncMetadata.TotalAfterFilter
		totalDups += p.SyncMetadata.DuplicatesRemoved
		for _, al := range p.Alerts {
			ids = append(ids, al.ExternalID)
		}
	}
	if sent[0].SyncMetadata.TotalFetched != 509 || sent[0].SyncMetadata.DuplicatesRemoved != 4 {
		t.Errorf("first chunk metadata = %+v, want total_fetched 509 and duplicates 4", sent[0].SyncMetadata)
	}
	if totalFetched != 1210 || totalAfter != 1201 || totalDups != 4 {
		t.Errorf("sums fetched/after/dups = %d/%d/%d, want 1210/1201/4", totalFetched, totalAfter, totalDups)
	}
	if !reflect.DeepEqual(ids, externalIDsOf(batch.Templates)) {
		t.Error("alerts were reordered, lost or duplicated across chunks")
	}
	if a.checkpoint != "cp-2" {
		t.Errorf("checkpoint = %q", a.checkpoint)
	}
}

func externalIDsOf(ts []models.AlertImportTemplate) []string {
	var out []string
	for _, t := range ts {
		out = append(out, t.ExternalID)
	}
	return out
}

func TestCollectAndSend_MetadataDatesAreTheWindow(t *testing.T) {
	coll := &fakeCollector{}
	b := batchOf(2, "cp-2")
	b.Templates[0].AlertDate = "2024-01-01" // old event time must not widen the period
	coll.push(b, nil)
	platform := &fakePlatform{}
	a := newTestAgent(t, coll, platform, nil)

	a.collectAndSend(context.Background(), nil)

	meta := platform.sent()[0].SyncMetadata
	if meta.DateFrom != "2026-10-23T12:00:00Z" || meta.DateTo != "2026-10-30T11:58:00Z" {
		t.Errorf("dates = %s .. %s, want the collection window", meta.DateFrom, meta.DateTo)
	}
}

func TestCollectAndSend_WindowFallbackToAlertDates(t *testing.T) {
	coll := &fakeCollector{}
	b := batchOf(2, "cp-2")
	b.WindowFrom, b.WindowTo = time.Time{}, time.Time{}
	b.Templates[0].AlertDate = "2026-10-20"
	coll.push(b, nil)
	platform := &fakePlatform{}
	a := newTestAgent(t, coll, platform, nil)
	a.collectAndSend(context.Background(), nil)

	meta := platform.sent()[0].SyncMetadata
	if meta.DateFrom != "2026-10-20T00:00:00Z" || meta.DateTo != "2026-10-29T23:59:59Z" {
		t.Errorf("dates = %s .. %s", meta.DateFrom, meta.DateTo)
	}
}

func TestCollectAndSend_FailedChunkBuffersTheRestWithoutPilingUp(t *testing.T) {
	coll := &fakeCollector{}
	coll.push(batchOf(1100, "cp-2"), nil)
	coll.push(batchOf(1100, "cp-2"), nil) // same window again: platform still down
	platform := &fakePlatform{respond: func(call int, p models.SyncPayload) (*models.SyncResponse, error) {
		if call == 0 {
			return okResponse(p), nil
		}
		return nil, errors.New("connection refused")
	}}
	buf := buffer.NewMemoryBuffer()
	a := newTestAgent(t, coll, platform, buf)
	a.checkpoint = "cp-1"

	a.collectAndSend(context.Background(), nil)
	batches, _ := buf.Peek(0, 10)
	if len(batches) != 2 || len(batches[0].Payload.Alerts) != 500 || len(batches[1].Payload.Alerts) != 100 {
		t.Fatalf("buffered %d batches, want chunks 2 and 3", len(batches))
	}
	if batches[0].Payload.SyncMetadata.DateFrom != "2026-10-23T12:00:00Z" {
		t.Errorf("buffered metadata = %+v", batches[0].Payload.SyncMetadata)
	}
	if a.checkpoint != "cp-1" {
		t.Errorf("checkpoint advanced to %q", a.checkpoint)
	}

	a.collectAndSend(context.Background(), nil)
	if got := bufLen(t, buf); got != 3 {
		// chunk 1 failed this time too, so chunks 1-3 are buffered; 2 and 3 replaced their older copies
		t.Errorf("buffer holds %d batches, want 3", got)
	}
}

// Regression (E2E P3): with the platform down the heartbeat stayed healthy
// for the whole 30-minute retry window, the collection loop waited that long
// and only then buffered the batch. Now the first failed attempt is reported
// and the batch is buffered after a retry window of a few minutes, whether
// the platform refuses connections or lets requests time out.
func TestCollectAndSend_PlatformDownIsReportedAtOnceAndBufferedWithinMinutes(t *testing.T) {
	tests := []struct {
		name    string
		attempt time.Duration // how long one failed POST takes
	}{
		{"connection refused", 0},
		{"request timeout", 90 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			coll := &fakeCollector{}
			coll.push(batchOf(3, "cp-2"), nil)
			var a *Agent
			var clock *fakeClock
			var seen []health.Report // the status the heartbeat would send during each retry
			platform := &fakePlatform{respond: func(call int, _ models.SyncPayload) (*models.SyncResponse, error) {
				if call > 0 {
					seen = append(seen, a.status.Report())
				}
				clock.Advance(tt.attempt)
				return nil, errPlatformDown
			}}
			buf := newSQLiteBuffer(t)
			a, clock = newOutageAgent(t, coll, platform, buf)
			a.checkpoint = "cp-1"

			start := clock.Now()
			a.collectAndSend(context.Background(), nil)
			elapsed := clock.Now().Sub(start)

			if len(seen) == 0 {
				t.Fatal("the failed POST was not retried")
			}
			for i, r := range seen {
				if r.Status != health.StatusDegraded || !strings.Contains(r.Detail, "connection refused") {
					t.Fatalf("status during retry %d = %+v, want degraded with the delivery error", i+1, r)
				}
			}
			if elapsed > 5*time.Minute {
				t.Errorf("the cycle waited %s for the platform, want at most 5 minutes", elapsed)
			}
			if n := bufLen(t, buf); n != 1 {
				t.Errorf("buffered = %d, want the batch stored when the retry window closed", n)
			}
			if _, saved := savedCheckpoint(t, a); saved || a.checkpoint != "cp-1" {
				t.Errorf("checkpoint advanced to %q", a.checkpoint)
			}
			if r := a.status.Report(); r.Status != health.StatusDegraded || r.BufferedBatches != 1 {
				t.Errorf("status after the cycle = %+v", r)
			}
		})
	}
}

// A retry that succeeds clears the delivery error at once, before the next
// chunk is sent.
func TestCollectAndSend_RetrySuccessClearsTheDeliveryError(t *testing.T) {
	coll := &fakeCollector{}
	coll.push(batchOf(700, "cp-2"), nil) // two chunks
	var a *Agent
	var seen []string
	platform := &fakePlatform{respond: func(call int, p models.SyncPayload) (*models.SyncResponse, error) {
		seen = append(seen, a.status.Report().Status)
		if call < 2 {
			return nil, &transport.HTTPError{Op: "sync", StatusCode: 503, Body: "unavailable"}
		}
		return okResponse(p), nil
	}}
	a, _ = newOutageAgent(t, coll, platform, buffer.NewMemoryBuffer())

	a.collectAndSend(context.Background(), nil)

	// chunk 1: fails, fails, succeeds; chunk 2: succeeds
	want := []string{health.StatusHealthy, health.StatusDegraded, health.StatusDegraded, health.StatusHealthy}
	if !reflect.DeepEqual(seen, want) {
		t.Errorf("status seen by each POST = %v, want %v", seen, want)
	}
	if r := a.status.Report(); r.Status != health.StatusHealthy || a.checkpoint != "cp-2" {
		t.Errorf("after the cycle: %+v, checkpoint %q", r, a.checkpoint)
	}
}

// A partial import is still reported after the next chunk succeeds.
func TestCollectAndSend_PartialChunkStaysReportedAfterALaterChunk(t *testing.T) {
	coll := &fakeCollector{}
	coll.push(batchOf(700, "cp-2"), nil)
	var a *Agent
	var seen []string
	platform := &fakePlatform{respond: func(call int, p models.SyncPayload) (*models.SyncResponse, error) {
		seen = append(seen, a.status.Report().Status)
		switch call {
		case 0:
			return &models.SyncResponse{Success: true, AlertsImported: len(p.Alerts) - 1, AlertsErrors: 1}, nil
		case 1:
			return nil, &transport.HTTPError{Op: "sync", StatusCode: 503, Body: "unavailable"}
		}
		return okResponse(p), nil
	}}
	a, _ = newOutageAgent(t, coll, platform, buffer.NewMemoryBuffer())

	a.collectAndSend(context.Background(), nil)

	if want := []string{health.StatusHealthy, health.StatusDegraded, health.StatusDegraded}; !reflect.DeepEqual(seen, want) {
		t.Errorf("status seen by each POST = %v, want %v", seen, want)
	}
	if r := a.status.Report(); r.Status != health.StatusDegraded || !strings.Contains(r.Detail, "only partially") || a.checkpoint != "" {
		t.Errorf("after the cycle: %+v, checkpoint %q", r, a.checkpoint)
	}
}

// With the short retry window an outage spans many cycles. Each one buffers
// the re-collected window under the same keys (one copy per chunk, the newest
// one); once the platform is back every buffered chunk is posted once, the
// re-collection right after the drain posts only the alerts that arrived since
// (not the drained ones again), the checkpoint advances and no alert is lost.
func TestCycle_OutageBuffersOneCopyPerChunkAndRecoversWithoutLoss(t *testing.T) {
	coll := &fakeCollector{}
	sizes := []int{700, 710, 720} // the same window, growing while the platform is down
	for _, n := range sizes {
		coll.push(batchOf(n, "cp-2"), nil)
	}
	coll.push(batchOf(730, "cp-2"), nil) // recovery cycle
	down := true
	platform := &fakePlatform{respond: func(_ int, p models.SyncPayload) (*models.SyncResponse, error) {
		if down {
			return nil, errPlatformDown
		}
		return okResponse(p), nil
	}}
	buf := newSQLiteBuffer(t)
	a, clock := newOutageAgent(t, coll, platform, buf)
	a.checkpoint = "cp-1"
	ctx := context.Background()

	for i, n := range sizes {
		start := clock.Now()
		a.cycle(ctx)
		if d := clock.Now().Sub(start); d > 5*time.Minute {
			t.Errorf("outage cycle %d waited %s for the platform", i+1, d)
		}
		batches, err := buf.Peek(0, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(batches) != 2 {
			t.Fatalf("outage cycle %d: buffer holds %d batches, want the window's 2 chunks once", i+1, len(batches))
		}
		if got := len(batches[0].Payload.Alerts) + len(batches[1].Payload.Alerts); got != n {
			t.Errorf("outage cycle %d: buffered %d alerts, want the newest copy (%d)", i+1, got, n)
		}
		if a.checkpoint != "cp-1" {
			t.Fatalf("checkpoint advanced to %q during the outage", a.checkpoint)
		}
	}
	if r := a.heartbeatStatus(ctx); r.Status != health.StatusDegraded || r.BufferedBatches != 2 {
		t.Errorf("status during the outage = %+v", r)
	}

	down = false
	before := len(platform.sent())
	a.cycle(ctx)
	recovery := platform.sent()[before:]
	if len(recovery) != 3 {
		t.Fatalf("recovery cycle posted %d chunks, want the 2 buffered ones and 1 with the alerts collected since", len(recovery))
	}
	assertPostedOnce(t, recovery, templates("a", 730))
	if got := len(recovery[0].Alerts) + len(recovery[1].Alerts); got != 720 {
		t.Errorf("drain posted %d alerts, want the 720 of the newest buffered copy", got)
	}
	if meta := recovery[2].SyncMetadata; len(recovery[2].Alerts) != 10 || meta.TotalFetched != 10 || meta.TotalAfterFilter != 10 {
		t.Errorf("collection posted %d alerts with metadata %+v, want only the 10 new ones, counted once", len(recovery[2].Alerts), meta)
	}
	if saved, _ := savedCheckpoint(t, a); saved != "cp-2" {
		t.Errorf("saved checkpoint = %q, want cp-2", saved)
	}
	if r := a.heartbeatStatus(ctx); r.Status != health.StatusHealthy || r.BufferedBatches != 0 {
		t.Errorf("status after recovery = %+v", r)
	}

	before = len(platform.sent())
	a.cycle(ctx)
	if got := len(platform.sent()) - before; got != 0 {
		t.Errorf("the cycle after recovery posted %d chunks, want none", got)
	}
}

// assertPostedOnce checks that every alert of want was posted exactly once
// in sent, and that nothing else was.
func assertPostedOnce(t *testing.T, sent []models.SyncPayload, want []models.AlertImportTemplate) {
	t.Helper()
	posted := map[string]int{}
	for _, p := range sent {
		for _, al := range p.Alerts {
			posted[al.ExternalID]++
		}
	}
	var wrong []string
	for _, id := range externalIDsOf(want) {
		if posted[id] != 1 {
			wrong = append(wrong, fmt.Sprintf("%s×%d", id, posted[id]))
		}
		delete(posted, id)
	}
	if len(wrong) > 0 {
		t.Errorf("%d of %d alerts were not posted exactly once (first: %s)", len(wrong), len(want), wrong[0])
	}
	if len(posted) > 0 {
		t.Errorf("%d unexpected alerts were posted", len(posted))
	}
}

// Regression (review P2): an outage longer than the 2-minute retry window but
// shorter than the old 30-minute one made the recovery cycle post every
// buffered alert twice: once from the drain and once from the re-collection of
// the window the checkpoint had not passed (4 POSTs and two sync logs for 700
// alerts, where the old window posted 2). The re-collection now skips what the
// drain delivered, so the window is posted once and the checkpoint advances.
func TestCycle_RecoveryAfterAShortOutagePostsTheWindowOnce(t *testing.T) {
	coll := &fakeCollector{}
	coll.push(batchOf(700, "cp-2"), nil) // two chunks, collected during the outage
	coll.push(batchOf(700, "cp-2"), nil) // the same window, collected again after it
	var clock *fakeClock
	var outageEnd time.Time
	platform := &fakePlatform{respond: func(_ int, p models.SyncPayload) (*models.SyncResponse, error) {
		if clock.Now().Before(outageEnd) {
			return nil, errPlatformDown
		}
		return okResponse(p), nil
	}}
	buf := newSQLiteBuffer(t)
	a, clock := newOutageAgent(t, coll, platform, buf)
	outageEnd = clock.Now().Add(5 * time.Minute)
	a.checkpoint = "cp-1"
	ctx := context.Background()

	start := clock.Now()
	a.cycle(ctx)
	if n := bufLen(t, buf); n != 2 || a.checkpoint != "cp-1" {
		t.Fatalf("after the outage cycle: buffered %d chunks, checkpoint %q; want 2 and cp-1", n, a.checkpoint)
	}

	clock.Advance(start.Add(15 * time.Minute).Sub(clock.Now())) // the next tick of a 15-minute interval
	before := len(platform.sent())
	a.cycle(ctx)
	recovery := platform.sent()[before:]

	if len(recovery) != 2 {
		t.Errorf("recovery cycle posted %d chunks, want the window's 2 chunks once", len(recovery))
	}
	assertPostedOnce(t, recovery, templates("a", 700))
	if got := coll.checkpoints; !reflect.DeepEqual(got, []string{"cp-1", "cp-1"}) {
		t.Errorf("collected from %v, want the window from cp-1 twice", got)
	}
	if saved, _ := savedCheckpoint(t, a); saved != "cp-2" || a.checkpoint != "cp-2" {
		t.Errorf("checkpoint saved=%q memory=%q, want cp-2", saved, a.checkpoint)
	}
	if r := a.heartbeatStatus(ctx); r.Status != health.StatusHealthy || r.BufferedBatches != 0 {
		t.Errorf("status after recovery = %+v", r)
	}
}

// Only alerts the platform accepted without errors in the drain are skipped:
// the alerts of a buffered batch it imported partially or refused, or of a
// batch buffered for another connection, are posted by the collection.
func TestCycle_CollectionSkipsOnlyWhatTheDrainGotAccepted(t *testing.T) {
	tests := []struct {
		name       string
		connection string
		drained    func(models.SyncPayload) (*models.SyncResponse, error)
		wantPosted int // alerts posted by the collection
	}{
		{"accepted", testConnectionID, func(p models.SyncPayload) (*models.SyncResponse, error) {
			return okResponse(p), nil
		}, 0},
		{"accepted with rejected or limit-skipped alerts", testConnectionID, func(p models.SyncPayload) (*models.SyncResponse, error) {
			return &models.SyncResponse{Success: true, AlertsRejected: 1, AlertsSkipped: 1, LimitReached: true}, nil
		}, 0},
		{"imported partially", testConnectionID, func(p models.SyncPayload) (*models.SyncResponse, error) {
			return &models.SyncResponse{Success: true, AlertsImported: len(p.Alerts) - 1, AlertsErrors: 1}, nil
		}, 3},
		{"refused", testConnectionID, func(models.SyncPayload) (*models.SyncResponse, error) {
			return nil, &transport.HTTPError{Op: "sync", StatusCode: 422, Body: "invalid"}
		}, 3},
		{"another connection", "0b7f0d3c-1111-4a2b-8c3d-4e5f6a7b8c9d", func(p models.SyncPayload) (*models.SyncResponse, error) {
			return okResponse(p), nil
		}, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := buffer.NewMemoryBuffer()
			if err := buf.Push(models.SyncPayload{ConnectionID: tt.connection, Alerts: templates("a", 3)}, "k"); err != nil {
				t.Fatal(err)
			}
			coll := &fakeCollector{}
			coll.push(batchOf(3, "cp-2"), nil)
			platform := &fakePlatform{respond: func(call int, p models.SyncPayload) (*models.SyncResponse, error) {
				if call == 0 {
					return tt.drained(p)
				}
				return okResponse(p), nil
			}}
			a := newTestAgent(t, coll, platform, buf)
			a.checkpoint = "cp-1"

			a.cycle(context.Background())

			posted := 0
			for _, p := range platform.sent()[1:] {
				posted += len(p.Alerts)
			}
			if posted != tt.wantPosted {
				t.Errorf("collection posted %d alerts, want %d", posted, tt.wantPosted)
			}
			if a.checkpoint != "cp-2" {
				t.Errorf("checkpoint = %q, want cp-2", a.checkpoint)
			}
		})
	}
}

// When the platform fails again in the middle of the drain, the collection
// skips the chunk that was accepted and posts the rest of the window.
func TestCycle_InterruptedDrainSkipsOnlyTheDeliveredChunk(t *testing.T) {
	buf := newSQLiteBuffer(t)
	all := templates("a", 700)
	for i, chunk := range [][]models.AlertImportTemplate{all[:500], all[500:]} {
		if err := buf.Push(models.SyncPayload{ConnectionID: testConnectionID, Alerts: chunk}, bufferKey(testConnectionID, "cp-1", i)); err != nil {
			t.Fatal(err)
		}
	}
	coll := &fakeCollector{}
	coll.push(batchOf(700, "cp-2"), nil)
	platform := &fakePlatform{respond: func(call int, p models.SyncPayload) (*models.SyncResponse, error) {
		if call == 1 { // the drain's second chunk
			return nil, errPlatformDown
		}
		return okResponse(p), nil
	}}
	a, _ := newOutageAgent(t, coll, platform, buf)
	a.checkpoint = "cp-1"

	a.cycle(context.Background())

	sent := platform.sent()
	if len(sent) != 3 {
		t.Fatalf("POSTs = %d, want drained chunk 1, failed chunk 2 and the collection", len(sent))
	}
	if got, want := externalIDsOf(sent[2].Alerts), externalIDsOf(all[500:]); !reflect.DeepEqual(got, want) {
		t.Errorf("collection posted %d alerts, want the 200 the drain did not deliver", len(got))
	}
	if saved, _ := savedCheckpoint(t, a); saved != "cp-2" {
		t.Errorf("saved checkpoint = %q, want cp-2", saved)
	}
}

func TestCollectAndSend_NothingNewStillPersistsAChangedCheckpoint(t *testing.T) {
	coll := &fakeCollector{}
	coll.push(collector.Batch{Checkpoint: "normalized"}, nil)
	platform := &fakePlatform{}
	a := newTestAgent(t, coll, platform, nil)
	a.checkpoint = "foreign"

	a.collectAndSend(context.Background(), nil)

	if saved, _ := savedCheckpoint(t, a); saved != "normalized" || len(platform.sent()) != 0 {
		t.Errorf("saved=%q posts=%d", saved, len(platform.sent()))
	}
}

func TestCollectAndSend_CollectErrorKeepsCheckpoint(t *testing.T) {
	coll := &fakeCollector{}
	coll.push(collector.Batch{}, errors.New("SIEM unreachable"))
	platform := &fakePlatform{}
	a := newTestAgent(t, coll, platform, nil)
	a.checkpoint = "cp-1"

	a.collectAndSend(context.Background(), nil)

	if a.checkpoint != "cp-1" || len(platform.sent()) != 0 {
		t.Errorf("checkpoint=%q posts=%d", a.checkpoint, len(platform.sent()))
	}
	if _, ok := savedCheckpoint(t, a); ok {
		t.Error("checkpoint file written after a failed collection")
	}
}

// --- drainBuffer ------------------------------------------------------------------------

func pushBatches(t *testing.T, buf buffer.Buffer, names ...string) {
	t.Helper()
	for _, name := range names {
		p := models.SyncPayload{
			ConnectionID: testConnectionID,
			Alerts:       templates(name, 1),
			SyncMetadata: models.SyncMetadata{DateFrom: "2026-10-23T12:00:00Z", DateTo: "2026-10-30T11:58:00Z", SIEMType: "stellar_cyber", AgentVersion: "v0", TotalFetched: 1, TotalAfterFilter: 1},
		}
		if err := buf.Push(p, ""); err != nil {
			t.Fatal(err)
		}
	}
}

func sentNames(ps []models.SyncPayload) []string {
	var out []string
	for _, p := range ps {
		out = append(out, strings.SplitN(p.Alerts[0].ExternalID, "-", 2)[0])
	}
	return out
}

func newSQLiteBuffer(t *testing.T) *buffer.SQLiteBuffer {
	t.Helper()
	b, err := buffer.NewSQLiteBuffer(filepath.Join(t.TempDir(), "buffer.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	return b
}

func TestDrainBuffer_KeepsUndeliveredBatches(t *testing.T) {
	buf := newSQLiteBuffer(t)
	pushBatches(t, buf, "b1", "b2", "b3")
	down := true
	platform := &fakePlatform{respond: func(call int, p models.SyncPayload) (*models.SyncResponse, error) {
		if down && call == 1 {
			return nil, errors.New("connection reset by peer")
		}
		return okResponse(p), nil
	}}
	a := newTestAgent(t, &fakeCollector{}, platform, buf)

	a.drainBuffer(context.Background())
	if got := sentNames(platform.sent()); !reflect.DeepEqual(got, []string{"b1", "b2"}) {
		t.Fatalf("sent %v, want b1 then the failing b2 (and stop)", got)
	}
	left, _ := buf.Peek(0, 10)
	if got := sentNames(payloadsOf(left)); !reflect.DeepEqual(got, []string{"b2", "b3"}) {
		t.Fatalf("buffer holds %v, want [b2 b3]", got)
	}

	down = false
	a.drainBuffer(context.Background())
	if n := bufLen(t, buf); n != 0 {
		t.Errorf("buffer holds %d batches after recovery", n)
	}
}

func payloadsOf(bs []buffer.BufferedBatch) []models.SyncPayload {
	var out []models.SyncPayload
	for _, b := range bs {
		out = append(out, b.Payload)
	}
	return out
}

func TestDrainBuffer_PermanentRejectionDoesNotBlockTheQueue(t *testing.T) {
	buf := newSQLiteBuffer(t)
	pushBatches(t, buf, "gone", "b2", "partial", "b4")
	platform := &fakePlatform{respond: func(call int, p models.SyncPayload) (*models.SyncResponse, error) {
		switch {
		case strings.HasPrefix(p.Alerts[0].ExternalID, "gone"):
			return nil, &transport.HTTPError{Op: "sync", StatusCode: 404, Body: "connection not found"}
		case strings.HasPrefix(p.Alerts[0].ExternalID, "partial"):
			return &models.SyncResponse{Success: true, AlertsErrors: 1}, nil
		}
		return okResponse(p), nil
	}}
	a := newTestAgent(t, &fakeCollector{}, platform, buf)

	a.drainBuffer(context.Background())

	left, _ := buf.Peek(0, 10)
	if got := sentNames(payloadsOf(left)); !reflect.DeepEqual(got, []string{"gone", "partial"}) {
		t.Errorf("buffer holds %v, want the rejected and the partial batch", got)
	}
	for _, b := range left {
		if b.Rejections != 1 {
			t.Errorf("batch %d: rejections = %d, want 1", b.ID, b.Rejections)
		}
	}
	if got := sentNames(platform.sent()); !reflect.DeepEqual(got, []string{"gone", "b2", "partial", "b4"}) {
		t.Errorf("sent %v", got)
	}
}

// Regression (review P3): a batch the platform keeps refusing (its connection
// was deleted: 404; or a partial import) used to be re-sent on every cycle
// forever and kept the heartbeat degraded. It is dropped after
// maxBufferedRejections refusals.
func TestDrainBuffer_RefusedBatchIsDroppedAfterRepeatedRejections(t *testing.T) {
	buf := newSQLiteBuffer(t)
	pushBatches(t, buf, "gone", "partial")
	platform := &fakePlatform{respond: func(_ int, p models.SyncPayload) (*models.SyncResponse, error) {
		if strings.HasPrefix(p.Alerts[0].ExternalID, "gone") {
			return nil, &transport.HTTPError{Op: "sync", StatusCode: 404, Body: "connection not found"}
		}
		return &models.SyncResponse{Success: true, AlertsErrors: 1}, nil
	}}
	a := newTestAgent(t, &fakeCollector{}, platform, buf)
	a.status.SetInit(nil)
	a.healthEvery = time.Hour

	for i := 1; i < maxBufferedRejections; i++ {
		a.drainBuffer(context.Background())
	}
	left, _ := buf.Peek(0, 10)
	if len(left) != 2 || left[0].Rejections != maxBufferedRejections-1 || left[1].Rejections != maxBufferedRejections-1 {
		t.Fatalf("after %d drains the buffer holds %+v, want both batches refused %d times", maxBufferedRejections-1, left, maxBufferedRejections-1)
	}
	if r := a.heartbeatStatus(context.Background()); r.Status != health.StatusDegraded {
		t.Errorf("status with refused batches waiting = %s, want degraded", r.Status)
	}

	a.drainBuffer(context.Background())
	if n := bufLen(t, buf); n != 0 {
		t.Fatalf("buffer holds %d batches after %d refusals, want them dropped", n, maxBufferedRejections)
	}
	if got := len(platform.sent()); got != 2*maxBufferedRejections {
		t.Errorf("posts = %d, want %d", got, 2*maxBufferedRejections)
	}
	a.drainBuffer(context.Background())
	if got := len(platform.sent()); got != 2*maxBufferedRejections {
		t.Errorf("a dropped batch was sent again (%d posts)", got)
	}
	if r := a.heartbeatStatus(context.Background()); r.Status != health.StatusHealthy || r.BufferedBatches != 0 {
		t.Errorf("status after dropping = %+v, want healthy with an empty buffer", r)
	}
}

// A batch that was refused before and is then accepted is delivered normally.
func TestDrainBuffer_RefusedThenAcceptedBatchIsDelivered(t *testing.T) {
	buf := buffer.NewMemoryBuffer()
	pushBatches(t, buf, "flaky")
	refuse := true
	platform := &fakePlatform{respond: func(_ int, p models.SyncPayload) (*models.SyncResponse, error) {
		if refuse {
			return nil, &transport.HTTPError{Op: "sync", StatusCode: 422, Body: "invalid"}
		}
		return okResponse(p), nil
	}}
	a := newTestAgent(t, &fakeCollector{}, platform, buf)
	a.drainBuffer(context.Background())
	refuse = false
	a.drainBuffer(context.Background())
	if n := bufLen(t, buf); n != 0 || len(platform.sent()) != 2 {
		t.Errorf("buffered = %d, posts = %d; want the batch delivered on the second drain", n, len(platform.sent()))
	}
}

// A delivered buffered batch clears the delivery error: the platform is
// reachable again, so the heartbeat recovers without waiting for a collection.
func TestDrainBuffer_DeliveryClearsTheDeliveryError(t *testing.T) {
	buf := buffer.NewMemoryBuffer()
	pushBatches(t, buf, "b1")
	down := true
	platform := &fakePlatform{respond: func(_ int, p models.SyncPayload) (*models.SyncResponse, error) {
		if down {
			return nil, errPlatformDown
		}
		return okResponse(p), nil
	}}
	a := newTestAgent(t, &fakeCollector{}, platform, buf)
	a.status.SetInit(nil)
	a.healthEvery = time.Hour

	a.drainBuffer(context.Background())
	if r := a.heartbeatStatus(context.Background()); r.Status != health.StatusDegraded || !strings.Contains(r.Detail, "delivery to the platform failed") {
		t.Errorf("status after a failed drain = %+v", r)
	}
	down = false
	a.drainBuffer(context.Background())
	if r := a.heartbeatStatus(context.Background()); r.Status != health.StatusHealthy || r.BufferedBatches != 0 {
		t.Errorf("status after the buffer was delivered = %+v, want healthy", r)
	}
}

func TestDrainBuffer_AuthErrorStopsDraining(t *testing.T) {
	buf := buffer.NewMemoryBuffer()
	pushBatches(t, buf, "b1", "b2")
	platform := &fakePlatform{respond: func(int, models.SyncPayload) (*models.SyncResponse, error) {
		return nil, &transport.HTTPError{Op: "sync", StatusCode: 401, Body: "invalid agent token"}
	}}
	a := newTestAgent(t, &fakeCollector{}, platform, buf)
	a.drainBuffer(context.Background())
	if len(platform.sent()) != 1 || bufLen(t, buf) != 2 {
		t.Errorf("posts=%d buffered=%d, want 1 and 2", len(platform.sent()), bufLen(t, buf))
	}
}

func TestDrainBuffer_SplitsLegacyBatchesAndFillsMetadata(t *testing.T) {
	buf := buffer.NewMemoryBuffer()
	legacy := models.SyncPayload{
		ConnectionID: testConnectionID,
		Alerts:       templates("old", 1200),
		SyncMetadata: buffer.DeriveMetadata(templates("old", 1200), time.Now()), // what the migration stores
	}
	if err := buf.Push(legacy, ""); err != nil {
		t.Fatal(err)
	}
	platform := &fakePlatform{}
	a := newTestAgent(t, &fakeCollector{}, platform, buf)

	a.drainBuffer(context.Background())

	sent := platform.sent()
	if len(sent) != 3 || len(sent[0].Alerts) != 500 || len(sent[2].Alerts) != 200 {
		t.Fatalf("POSTs = %d", len(sent))
	}
	total := 0
	for _, p := range sent {
		if p.SyncMetadata.SIEMType != "stellar_cyber" || p.SyncMetadata.AgentVersion == "" || p.SyncMetadata.DateFrom != "2026-10-29T00:00:00Z" {
			t.Errorf("metadata = %+v", p.SyncMetadata)
		}
		total += p.SyncMetadata.TotalFetched
	}
	if total != 1200 || bufLen(t, buf) != 0 {
		t.Errorf("total_fetched sum = %d, buffered = %d", total, bufLen(t, buf))
	}
}

func TestDrainBuffer_DrainsEveryPage(t *testing.T) {
	buf := newSQLiteBuffer(t)
	var names []string
	for i := 0; i < 25; i++ {
		names = append(names, fmt.Sprintf("p%02d", i))
	}
	pushBatches(t, buf, names...)
	platform := &fakePlatform{}
	a := newTestAgent(t, &fakeCollector{}, platform, buf)
	a.drainBuffer(context.Background())
	if got := sentNames(platform.sent()); !reflect.DeepEqual(got, names) {
		t.Errorf("sent %v", got)
	}
	if n := bufLen(t, buf); n != 0 {
		t.Errorf("buffered = %d", n)
	}
}
