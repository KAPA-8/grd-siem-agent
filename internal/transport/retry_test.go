package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
)

var fastRetry = RetryConfig{InitialInterval: time.Millisecond, MaxInterval: 2 * time.Millisecond, MaxElapsedTime: 50 * time.Millisecond}

// fakeClock is a simulated Clock: its timers fire at once and move the time
// forward by the wait, so a retry window of minutes runs instantly.
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

func TestIsPermanent(t *testing.T) {
	tests := []struct {
		err  error
		want bool
	}{
		{&HTTPError{StatusCode: 400}, true},
		{&HTTPError{StatusCode: 401}, true},
		{&HTTPError{StatusCode: 404}, true},
		{&HTTPError{StatusCode: 413}, true},
		{&HTTPError{StatusCode: 499}, true},
		{&HTTPError{StatusCode: 408}, false},
		{&HTTPError{StatusCode: 429}, false},
		{&HTTPError{StatusCode: 500}, false},
		{&HTTPError{StatusCode: 503}, false},
		{fmt.Errorf("wrapped: %w", &HTTPError{StatusCode: 422}), true},
		{errors.New("connection refused"), false},
		{nil, false},
	}
	for _, tt := range tests {
		if got := IsPermanent(tt.err); got != tt.want {
			t.Errorf("IsPermanent(%v) = %v, want %v", tt.err, got, tt.want)
		}
	}
}

func TestWithRetry_PermanentErrorStopsImmediately(t *testing.T) {
	attempts := 0
	err := WithRetry(context.Background(), fastRetry, "sync", func() error {
		attempts++
		return &HTTPError{Op: "sync", StatusCode: 400, Body: "bad payload"}
	})
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
	if StatusCode(err) != 400 {
		t.Errorf("err = %v, want the 400 to be preserved", err)
	}
}

func TestWithRetry_TransientErrorsAreRetried(t *testing.T) {
	for _, status := range []int{408, 429, 500, 503} {
		attempts := 0
		err := WithRetry(context.Background(), fastRetry, "sync", func() error {
			attempts++
			if attempts < 3 {
				return &HTTPError{Op: "sync", StatusCode: status}
			}
			return nil
		})
		if err != nil || attempts != 3 {
			t.Errorf("status %d: err=%v attempts=%d", status, err, attempts)
		}
	}
}

func TestWithRetry_StopsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	attempts := 0
	err := WithRetry(ctx, RetryConfig{InitialInterval: time.Millisecond, MaxInterval: time.Millisecond, MaxElapsedTime: time.Minute}, "sync", func() error {
		attempts++
		if attempts == 2 {
			cancel()
		}
		return errors.New("down")
	})
	if err == nil || attempts > 3 {
		t.Errorf("err=%v attempts=%d", err, attempts)
	}
}

func TestWithRetryNotify_ReportsEveryFailedAttempt(t *testing.T) {
	errDown := errors.New("connection refused")
	tests := []struct {
		name     string
		results  []error // one per attempt; then success
		wantErr  bool
		wantSeen int
	}{
		{"recovers after two failures", []error{errDown, &HTTPError{Op: "sync", StatusCode: 503}}, false, 2},
		{"permanent error", []error{&HTTPError{Op: "sync", StatusCode: 400}}, true, 1},
		{"succeeds at once", nil, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attempts := 0
			var seen []error
			err := WithRetryNotify(context.Background(), fastRetry, "sync", func() error {
				attempts++
				if attempts <= len(tt.results) {
					return tt.results[attempts-1]
				}
				return nil
			}, func(err error) { seen = append(seen, err) })
			if (err != nil) != tt.wantErr || len(seen) != tt.wantSeen {
				t.Fatalf("err=%v, failures reported=%v; want error=%v and %d failures", err, seen, tt.wantErr, tt.wantSeen)
			}
			for i, e := range seen {
				if e != tt.results[i] {
					t.Errorf("failure %d reported as %v, want %v", i+1, e, tt.results[i])
				}
			}
		})
	}
}

// The last attempt of a window that runs out is reported too.
func TestWithRetryNotify_ReportsTheLastAttempt(t *testing.T) {
	attempts, reported := 0, 0
	err := WithRetryNotify(context.Background(), fastRetry, "sync", func() error {
		attempts++
		return errors.New("connection refused")
	}, func(error) { reported++ })
	if err == nil || reported != attempts {
		t.Errorf("err=%v attempts=%d reported=%d, want every attempt reported", err, attempts, reported)
	}
}

// Regression (E2E P3): with the platform down, /sync was retried for 30
// minutes while the collection loop waited and nothing was buffered. The
// window is now a couple of minutes, long enough to retry a request that hit
// syncTimeout once.
func TestSyncRetryConfig_GivesUpWithinMinutes(t *testing.T) {
	tests := []struct {
		name        string
		attempt     time.Duration // how long one failed request takes
		minAttempts int
		minElapsed  time.Duration
	}{
		{"connection refused", 0, 5, time.Minute},
		{"request timeout", syncTimeout, 2, 2 * syncTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := SyncRetryConfig()
			clock := newFakeClock()
			cfg.Clock = clock
			start := clock.Now()
			attempts := 0
			err := WithRetry(context.Background(), cfg, "sync", func() error {
				attempts++
				clock.Advance(tt.attempt)
				return errors.New("dial tcp 127.0.0.1:39999: connect: connection refused")
			})
			elapsed := clock.Now().Sub(start)
			if err == nil {
				t.Fatal("WithRetry = nil, want the last error")
			}
			if elapsed > cfg.MaxElapsedTime+syncTimeout || elapsed > 5*time.Minute {
				t.Errorf("gave up after %s, want at most %s", elapsed, cfg.MaxElapsedTime+syncTimeout)
			}
			if attempts < tt.minAttempts || elapsed < tt.minElapsed {
				t.Errorf("%d attempts over %s, want at least %d attempts over %s", attempts, elapsed, tt.minAttempts, tt.minElapsed)
			}
		})
	}
}
