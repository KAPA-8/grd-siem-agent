package transport

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

var fastRetry = RetryConfig{InitialInterval: time.Millisecond, MaxInterval: 2 * time.Millisecond, MaxElapsedTime: 50 * time.Millisecond}

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
