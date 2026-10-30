package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

type exitRecorder struct{ codes chan int }

func newExitRecorder() *exitRecorder { return &exitRecorder{codes: make(chan int, 1)} }

func (e *exitRecorder) exit(code int) { e.codes <- code }

func (e *exitRecorder) wait(t *testing.T) (int, bool) {
	t.Helper()
	select {
	case code := <-e.codes:
		return code, true
	case <-time.After(5 * time.Second):
		return 0, false
	}
}

// B5: a fatal error in service mode used to leave a zombie service.
func TestService_FatalErrorExitsNonZero(t *testing.T) {
	rec := newExitRecorder()
	svc := &agentService{run: func(context.Context) error { return errors.New("config validation: platform.url is required") }, exit: rec.exit}
	if err := svc.Start(nil); err != nil {
		t.Fatal(err)
	}
	code, ok := rec.wait(t)
	if !ok || code != 1 {
		t.Fatalf("exit code = %d (called=%v), want 1", code, ok)
	}
	<-svc.done
}

func TestService_UnexpectedReturnExitsNonZero(t *testing.T) {
	rec := newExitRecorder()
	svc := &agentService{run: func(context.Context) error { return nil }, exit: rec.exit}
	_ = svc.Start(nil)
	if code, ok := rec.wait(t); !ok || code != 1 {
		t.Fatalf("exit code = %d (called=%v), want 1", code, ok)
	}
}

func TestService_StopIsGracefulAndDoesNotExit(t *testing.T) {
	rec := newExitRecorder()
	started := make(chan struct{})
	svc := &agentService{run: func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		return ctx.Err()
	}, exit: rec.exit}
	_ = svc.Start(nil)
	<-started
	if err := svc.Stop(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case code := <-rec.codes:
		t.Fatalf("exit(%d) called on a requested stop", code)
	default:
	}
}

// Stop right after Start must not deadlock or race (the cancel func is set
// before the goroutine starts).
func TestService_StopImmediatelyAfterStart(t *testing.T) {
	rec := newExitRecorder()
	svc := &agentService{run: func(ctx context.Context) error { <-ctx.Done(); return nil }, exit: rec.exit}
	_ = svc.Start(nil)
	done := make(chan struct{})
	go func() { _ = svc.Stop(nil); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Stop deadlocked")
	}
}

func TestService_MissingConfigExitsNonZero(t *testing.T) {
	configPath = filepath.Join(t.TempDir(), "missing.yaml")
	rec := newExitRecorder()
	svc := newAgentService()
	svc.exit = rec.exit
	_ = svc.Start(nil)
	if code, ok := rec.wait(t); !ok || code != 1 {
		t.Fatalf("exit code = %d (called=%v), want 1", code, ok)
	}
}
