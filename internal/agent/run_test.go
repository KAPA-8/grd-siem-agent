package agent

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/buffer"
	"github.com/grd-platform/grd-siem-agent/internal/collector"
	"github.com/grd-platform/grd-siem-agent/internal/health"
	"github.com/grd-platform/grd-siem-agent/internal/models"
	"github.com/grd-platform/grd-siem-agent/internal/transport"
)

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

type closeTracker struct {
	buffer.Buffer
	mu     sync.Mutex
	closed bool
}

func (c *closeTracker) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return c.Buffer.Close()
}

// The heartbeat starts before collector Init, reports "error" while Init
// keeps failing, and Init is retried until it succeeds (B5, B13).
func TestRun_HeartbeatFirstAndInitRetried(t *testing.T) {
	errDown := errors.New("dial tcp 10.0.0.5:443: connection refused")
	coll := &fakeCollector{initErrs: []error{errDown, errDown, errDown}}
	coll.push(batchOf(2, "cp-1"), nil)
	platform := &fakePlatform{}
	buf := &closeTracker{Buffer: buffer.NewMemoryBuffer()}
	a := newTestAgent(t, coll, platform, buf)
	a.initRetry = transport.RetryConfig{InitialInterval: 20 * time.Millisecond, MaxInterval: 20 * time.Millisecond}
	a.heartbeat = health.NewHeartbeatService(platform, 2*time.Millisecond, "h", 1, a.heartbeatStatus)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	waitFor(t, "the alerts to be sent after init", func() bool { return len(platform.sent()) == 1 })
	waitFor(t, "a healthy heartbeat", func() bool {
		platform.mu.Lock()
		defer platform.mu.Unlock()
		return len(platform.heartbeats) > 0 && platform.heartbeats[len(platform.heartbeats)-1].Status == health.StatusHealthy
	})
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run = %v, want nil on shutdown", err)
	}

	coll.mu.Lock()
	initCalls, closed := coll.initCalls, coll.closed
	coll.mu.Unlock()
	if initCalls != 4 {
		t.Errorf("Init calls = %d, want 4 (three failures, then success)", initCalls)
	}
	if !closed || !buf.closed {
		t.Errorf("collector closed=%v buffer closed=%v", closed, buf.closed)
	}

	platform.mu.Lock()
	defer platform.mu.Unlock()
	sawError := false
	for _, hb := range platform.heartbeats {
		if hb.Status == health.StatusError {
			sawError = true
			break
		}
		if hb.Status == health.StatusHealthy {
			break
		}
	}
	if !sawError {
		t.Errorf("no error heartbeat before init succeeded: %+v", platform.heartbeats)
	}
	if a.checkpoint != "cp-1" {
		t.Errorf("checkpoint = %q", a.checkpoint)
	}
}

func TestRun_CancelDuringInitRetriesReturns(t *testing.T) {
	coll := &fakeCollector{}
	for i := 0; i < 1000; i++ {
		coll.initErrs = append(coll.initErrs, errors.New("down"))
	}
	a := newTestAgent(t, coll, &fakePlatform{}, nil)
	a.initRetry = transport.RetryConfig{InitialInterval: time.Hour, MaxInterval: time.Hour}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()
	waitFor(t, "the first init attempt", func() bool {
		coll.mu.Lock()
		defer coll.mu.Unlock()
		return coll.initCalls == 1
	})
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel while waiting to retry Init")
	}
}

func TestHeartbeatStatus_ReflectsCollectionAndDelivery(t *testing.T) {
	coll := &fakeCollector{}
	platform := &fakePlatform{}
	buf := buffer.NewMemoryBuffer()
	a := newTestAgent(t, coll, platform, buf)
	a.healthEvery = time.Hour
	ctx := context.Background()

	if r := a.heartbeatStatus(ctx); r.Status != health.StatusDegraded || r.Detail != "starting" {
		t.Errorf("before init: %+v", r)
	}
	if err := a.initCollector(ctx); err != nil {
		t.Fatal(err)
	}
	if r := a.heartbeatStatus(ctx); r.Status != health.StatusHealthy {
		t.Errorf("after init: %+v", r)
	}

	coll.push(batchOf(1, "cp"), errors.New("401 from SIEM"))
	a.collectAndSend(ctx)
	if r := a.heartbeatStatus(ctx); r.Status != health.StatusError {
		t.Errorf("after a failed collection: %+v", r)
	}

	coll.push(batchOf(1, "cp-2"), nil)
	platform.respond = func(int, models.SyncPayload) (*models.SyncResponse, error) {
		return nil, &transport.HTTPError{Op: "sync", StatusCode: 400, Body: "bad"}
	}
	a.collectAndSend(ctx)
	r := a.heartbeatStatus(ctx)
	if r.Status != health.StatusDegraded || r.BufferedBatches != 1 {
		t.Errorf("after a failed delivery: %+v", r)
	}

	platform.respond = nil
	a.drainBuffer(ctx)
	coll.push(batchOf(1, "cp-3"), nil)
	a.collectAndSend(ctx)
	if r := a.heartbeatStatus(ctx); r.Status != health.StatusHealthy || r.BufferedBatches != 0 {
		t.Errorf("after recovery: %+v", r)
	}
}

func TestHeartbeatStatus_RunsHealthCheckPeriodically(t *testing.T) {
	coll := &fakeCollector{}
	a := newTestAgent(t, coll, &fakePlatform{}, nil)
	ctx := context.Background()
	if err := a.initCollector(ctx); err != nil {
		t.Fatal(err)
	}

	a.healthEvery = time.Hour
	a.heartbeatStatus(ctx)
	if coll.healthCalls != 0 {
		t.Errorf("health check ran right after Init (%d calls)", coll.healthCalls)
	}

	a.healthEvery = 0
	coll.healthErr = errors.New("token expired and refresh failed")
	if r := a.heartbeatStatus(ctx); r.Status != health.StatusError || coll.healthCalls != 1 {
		t.Errorf("failing health check: %+v (calls %d)", r, coll.healthCalls)
	}
	coll.healthErr = nil
	if r := a.heartbeatStatus(ctx); r.Status != health.StatusHealthy || coll.healthCalls != 2 {
		t.Errorf("recovered health check: %+v (calls %d)", r, coll.healthCalls)
	}
}

// gatedCollector blocks Collect or HealthCheck until released and records
// whether the two ever ran at the same time.
type gatedCollector struct {
	fakeCollector
	gateCollect, gateHealth bool
	started                 chan string
	release                 chan struct{}

	mu                      sync.Mutex
	active, overlaps        int
	collectCalls, healthRun int
}

func newGatedCollector() *gatedCollector {
	return &gatedCollector{started: make(chan string, 4), release: make(chan struct{})}
}

func (g *gatedCollector) enter() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active++
	if g.active > 1 {
		g.overlaps++
	}
}

func (g *gatedCollector) leave() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.active--
}

func (g *gatedCollector) counts() (collects, healths, overlaps int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.collectCalls, g.healthRun, g.overlaps
}

func (g *gatedCollector) Collect(ctx context.Context, checkpoint string) (collector.Batch, error) {
	g.enter()
	defer g.leave()
	g.mu.Lock()
	g.collectCalls++
	g.mu.Unlock()
	if g.gateCollect {
		g.started <- "collect"
		<-g.release
	}
	return g.fakeCollector.Collect(ctx, checkpoint)
}

func (g *gatedCollector) HealthCheck(ctx context.Context) error {
	g.enter()
	defer g.leave()
	g.mu.Lock()
	g.healthRun++
	g.mu.Unlock()
	if g.gateHealth {
		g.started <- "health"
		<-g.release
	}
	return g.fakeCollector.HealthCheck(ctx)
}

// Regression (review P3): the heartbeat's health check ran while Collect was
// paging, so the SIEM saw concurrent requests and a health check stuck
// behind the collection's token exchange reported "error". A due health
// check is now skipped while a collection runs, and a successful collection
// counts as a health check.
func TestHeartbeatStatus_HealthCheckSkippedWhileCollecting(t *testing.T) {
	coll := newGatedCollector()
	coll.gateCollect = true
	a := newAgent(testConfig(t), coll, &fakePlatform{}, buffer.NewMemoryBuffer())
	ctx := context.Background()
	if err := a.initCollector(ctx); err != nil {
		t.Fatal(err)
	}
	a.healthEvery = 0 // always due

	done := make(chan struct{})
	go func() { a.collectAndSend(ctx); close(done) }()
	<-coll.started
	if r := a.heartbeatStatus(ctx); r.Status != health.StatusHealthy {
		t.Errorf("status while collecting = %+v", r)
	}
	if _, healths, _ := coll.counts(); healths != 0 {
		t.Errorf("health check ran during Collect (%d calls)", healths)
	}
	close(coll.release)
	<-done

	a.healthEvery = time.Hour
	a.heartbeatStatus(ctx)
	if _, healths, _ := coll.counts(); healths != 0 {
		t.Errorf("health check ran right after a successful collection (%d calls)", healths)
	}
	a.healthEvery = 0
	a.heartbeatStatus(ctx)
	if collects, healths, overlaps := coll.counts(); collects != 1 || healths != 1 || overlaps != 0 {
		t.Errorf("collects=%d healths=%d overlaps=%d, want 1/1/0", collects, healths, overlaps)
	}
}

// A collection that starts while a health check runs waits for it.
func TestCollectAndSend_WaitsForARunningHealthCheck(t *testing.T) {
	coll := newGatedCollector()
	coll.gateHealth = true
	a := newAgent(testConfig(t), coll, &fakePlatform{}, buffer.NewMemoryBuffer())
	ctx := context.Background()
	if err := a.initCollector(ctx); err != nil {
		t.Fatal(err)
	}
	a.healthEvery = 0

	hbDone := make(chan struct{})
	go func() { a.heartbeatStatus(ctx); close(hbDone) }()
	<-coll.started
	collectDone := make(chan struct{})
	go func() { a.collectAndSend(ctx); close(collectDone) }()
	time.Sleep(50 * time.Millisecond) // give Collect a chance to run if it could
	if collects, _, _ := coll.counts(); collects != 0 {
		t.Errorf("Collect ran during a health check (%d calls)", collects)
	}
	close(coll.release)
	<-hbDone
	<-collectDone
	if collects, healths, overlaps := coll.counts(); collects != 1 || healths != 1 || overlaps != 0 {
		t.Errorf("collects=%d healths=%d overlaps=%d, want 1/1/0", collects, healths, overlaps)
	}
}
