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

			a.collectAndSend(context.Background())

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
			a.collectAndSend(context.Background())

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

	a.collectAndSend(context.Background())

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

	a.collectAndSend(context.Background())

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
	a.collectAndSend(context.Background())

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

	a.collectAndSend(context.Background())
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

	a.collectAndSend(context.Background())
	if got := bufLen(t, buf); got != 3 {
		// chunk 1 failed this time too, so chunks 1-3 are buffered; 2 and 3 replaced their older copies
		t.Errorf("buffer holds %d batches, want 3", got)
	}
}

func TestCollectAndSend_NothingNewStillPersistsAChangedCheckpoint(t *testing.T) {
	coll := &fakeCollector{}
	coll.push(collector.Batch{Checkpoint: "normalized"}, nil)
	platform := &fakePlatform{}
	a := newTestAgent(t, coll, platform, nil)
	a.checkpoint = "foreign"

	a.collectAndSend(context.Background())

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

	a.collectAndSend(context.Background())

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
