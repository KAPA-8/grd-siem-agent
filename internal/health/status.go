package health

import (
	"fmt"
	"sync"
)

// Heartbeat status values understood by the platform.
const (
	StatusHealthy  = "healthy"
	StatusDegraded = "degraded"
	StatusError    = "error"
)

// maxDetailLen bounds the status detail sent with each heartbeat.
const maxDetailLen = 500

// Report is the agent state sent with a heartbeat.
type Report struct {
	Status          string
	Detail          string
	BufferedBatches int
}

// Tracker records the outcome of the agent's work so the heartbeat reports
// real health. It is safe for concurrent use.
//
//   - error: the collector could not be initialized, or the last contact with
//     the SIEM (a collection or a health check) failed.
//   - degraded: still starting, the last delivery to the platform failed or
//     was partial, or batches are waiting in the buffer.
//   - healthy: otherwise.
type Tracker struct {
	mu          sync.Mutex
	initialized bool
	initErr     error
	siemErr     error
	deliveryErr error
	buffered    int
}

// SetInit records the result of a collector Init attempt.
func (t *Tracker) SetInit(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.initErr = err
	if err == nil {
		t.initialized = true
	}
}

// Initialized reports whether the collector was initialized.
func (t *Tracker) Initialized() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.initialized
}

// SetSIEM records the latest collection or health check result.
func (t *Tracker) SetSIEM(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.siemErr = err
}

// SetDelivery records the latest delivery result (nil when every alert was
// accepted or there was nothing to send).
func (t *Tracker) SetDelivery(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.deliveryErr = err
}

// SetBuffered records how many batches wait in the buffer.
func (t *Tracker) SetBuffered(n int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buffered = n
}

// Report returns the current status.
func (t *Tracker) Report() Report {
	t.mu.Lock()
	defer t.mu.Unlock()
	r := Report{Status: StatusHealthy, BufferedBatches: t.buffered}
	switch {
	case !t.initialized && t.initErr != nil:
		r.Status, r.Detail = StatusError, "collector init failed: "+t.initErr.Error()
	case !t.initialized:
		r.Status, r.Detail = StatusDegraded, "starting"
	case t.siemErr != nil:
		r.Status, r.Detail = StatusError, "SIEM unavailable: "+t.siemErr.Error()
	case t.deliveryErr != nil:
		r.Status, r.Detail = StatusDegraded, "delivery to the platform failed: "+t.deliveryErr.Error()
	case t.buffered > 0:
		r.Status, r.Detail = StatusDegraded, fmt.Sprintf("%d batches waiting in the buffer", t.buffered)
	}
	if len(r.Detail) > maxDetailLen {
		r.Detail = r.Detail[:maxDetailLen] + "..."
	}
	return r
}
