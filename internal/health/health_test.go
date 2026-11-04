package health

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/grd-platform/grd-siem-agent/internal/models"
)

func TestTracker_Report(t *testing.T) {
	errSIEM := errors.New("dial tcp: connection refused")
	tests := []struct {
		name       string
		setup      func(*Tracker)
		wantStatus string
		wantDetail string
	}{
		{"starting", func(*Tracker) {}, StatusDegraded, "starting"},
		{"init failed", func(tr *Tracker) { tr.SetInit(errSIEM) }, StatusError, "collector init failed"},
		{"init recovered", func(tr *Tracker) { tr.SetInit(errSIEM); tr.SetInit(nil) }, StatusHealthy, ""},
		{"collection failed", func(tr *Tracker) { tr.SetInit(nil); tr.SetSIEM(errSIEM) }, StatusError, "SIEM unavailable"},
		{"siem recovered", func(tr *Tracker) { tr.SetInit(nil); tr.SetSIEM(errSIEM); tr.SetSIEM(nil) }, StatusHealthy, ""},
		{"delivery failed", func(tr *Tracker) { tr.SetInit(nil); tr.SetDelivery(errors.New("sync failed (503)")) }, StatusDegraded, "delivery to the platform failed"},
		{"siem error wins over delivery", func(tr *Tracker) {
			tr.SetInit(nil)
			tr.SetDelivery(errors.New("x"))
			tr.SetSIEM(errSIEM)
		}, StatusError, "SIEM unavailable"},
		{"buffered batches", func(tr *Tracker) { tr.SetInit(nil); tr.SetBuffered(3) }, StatusDegraded, "3 batches waiting"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := &Tracker{}
			tt.setup(tr)
			r := tr.Report()
			if r.Status != tt.wantStatus || !strings.Contains(r.Detail, tt.wantDetail) {
				t.Errorf("Report = %+v, want %s containing %q", r, tt.wantStatus, tt.wantDetail)
			}
		})
	}
}

func TestTracker_DetailIsBounded(t *testing.T) {
	tr := &Tracker{}
	tr.SetInit(errors.New(strings.Repeat("x", 2000)))
	if d := tr.Report().Detail; len(d) > maxDetailLen+3 {
		t.Errorf("detail length = %d", len(d))
	}
}

type recordingSender struct {
	mu   sync.Mutex
	sent []models.HeartbeatPayload
	err  error
}

func (r *recordingSender) SendHeartbeat(_ context.Context, p models.HeartbeatPayload) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, p)
	return r.err
}

func (r *recordingSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sent)
}

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

func TestHeartbeat_SendsStatusImmediatelyAndPeriodically(t *testing.T) {
	sender := &recordingSender{err: errors.New("platform down")} // failures must not stop the loop
	tracker := &Tracker{}
	tracker.SetInit(errors.New("401 invalid credentials"))
	hb := NewHeartbeatService(sender, 5*time.Millisecond, "collector-01", 1, func(context.Context) Report { return tracker.Report() })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { hb.Run(ctx); close(done) }()

	waitFor(t, "three heartbeats", func() bool { return sender.count() >= 3 })
	tracker.SetInit(nil)
	waitFor(t, "a healthy heartbeat", func() bool {
		sender.mu.Lock()
		defer sender.mu.Unlock()
		return sender.sent[len(sender.sent)-1].Status == StatusHealthy
	})
	cancel()
	<-done

	first := sender.sent[0]
	if first.Status != StatusError || !strings.Contains(first.StatusDetail, "401") || first.Hostname != "collector-01" ||
		first.OSInfo != runtime.GOOS+"/"+runtime.GOARCH || first.ActiveConnections != 1 || first.AgentVersion == "" {
		t.Errorf("first heartbeat = %+v", first)
	}
}

func TestHeartbeat_NonPositiveIntervalUsesDefault(t *testing.T) {
	hb := NewHeartbeatService(&recordingSender{}, 0, "h", 1, nil)
	if hb.interval != DefaultInterval {
		t.Errorf("interval = %v", hb.interval)
	}
	sender := &recordingSender{}
	hb = NewHeartbeatService(sender, -time.Second, "", 1, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { hb.Run(ctx); close(done) }() // must not panic
	waitFor(t, "the first heartbeat", func() bool { return sender.count() == 1 })
	cancel()
	<-done
	if sender.sent[0].Status != StatusHealthy || sender.sent[0].Hostname == "" {
		t.Errorf("heartbeat = %+v", sender.sent[0])
	}
}
