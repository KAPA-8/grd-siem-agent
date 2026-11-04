package transport

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/rs/zerolog/log"
)

// RetryConfig controls the exponential backoff behavior.
type RetryConfig struct {
	InitialInterval time.Duration
	MaxInterval     time.Duration
	MaxElapsedTime  time.Duration

	// Clock measures MaxElapsedTime and waits between attempts. nil means
	// the system clock; tests simulate a retry window of minutes with it.
	Clock Clock
}

// Clock is the time source of WithRetry.
type Clock interface {
	Now() time.Time
	// NewTimer returns the timer one retry loop waits on between attempts.
	NewTimer() backoff.Timer
}

// SyncRetryConfig is the retry policy of POST /sync: about 1s, 2s, 4s, ... up
// to 30s between attempts, for at most 2 minutes. Every wait is randomized by
// ±50% (see WithRetryNotify), so the gaps actually range from 0.5s to 45s.
// A permanent error (see IsPermanent) is not retried at all.
//
// The window is longer than syncTimeout (90s), so a request that timed out
// is retried at least once, and it rides out a platform restart or a short
// network outage. It is short on purpose: the collection loop waits for it,
// and an attempt that starts just before the window closes still runs for up
// to syncTimeout, so a cycle waits at most about 3.5 minutes, well within the
// default 15-minute interval. A longer outage is handled by the buffer (the
// undelivered chunks are stored as soon as the window closes and every next
// cycle retries them) and by the checkpoint, which only advances once the
// alerts were delivered.
func SyncRetryConfig() RetryConfig {
	return RetryConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		MaxElapsedTime:  2 * time.Minute,
	}
}

// HTTPError is a non-2xx answer from the platform.
type HTTPError struct {
	Op         string // "sync", "heartbeat", ...
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s failed (%d): %s", e.Op, e.StatusCode, e.Body)
}

// StatusCode returns the HTTP status of a platform error, or 0.
func StatusCode(err error) int {
	var httpErr *HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode
	}
	return 0
}

// IsPermanent reports whether retrying cannot help: a 4xx answer other than
// 408 (request timeout) and 429 (too many requests). A bad payload, a revoked
// token or a deleted connection will fail again on every attempt.
func IsPermanent(err error) bool {
	code := StatusCode(err)
	return code >= 400 && code < 500 && code != 408 && code != 429
}

// WithRetry wraps an operation with exponential backoff retry logic.
// The operation function should return nil on success.
// It does not retry permanent errors (see IsPermanent) nor context cancellation.
func WithRetry(ctx context.Context, cfg RetryConfig, operationName string, operation func() error) error {
	return WithRetryNotify(ctx, cfg, operationName, operation, nil)
}

// WithRetryNotify is WithRetry with a callback run after every failed
// attempt, the last one and a permanent error included, so the caller can
// report the failure while the retries are still running. onFailure may be
// nil.
func WithRetryNotify(ctx context.Context, cfg RetryConfig, operationName string, operation func() error, onFailure func(error)) error {
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = cfg.InitialInterval
	b.MaxInterval = cfg.MaxInterval
	b.MaxElapsedTime = cfg.MaxElapsedTime
	b.Multiplier = 2
	// Each wait is the nominal interval ±50%, so agents that lost the
	// platform at the same time do not retry in lockstep when it comes back.
	b.RandomizationFactor = 0.5

	var timer backoff.Timer // nil: backoff's system timer
	if cfg.Clock != nil {
		b.Clock = cfg.Clock
		timer = cfg.Clock.NewTimer()
	}

	bCtx := backoff.WithContext(b, ctx)

	attempt := 0
	err := backoff.RetryNotifyWithTimer(func() error {
		attempt++
		err := operation()
		if err == nil {
			return nil
		}
		if onFailure != nil {
			onFailure(err)
		}
		if IsPermanent(err) {
			log.Error().
				Err(err).
				Int("attempt", attempt).
				Str("operation", operationName).
				Msg("operation failed with a permanent error, not retrying")
			return backoff.Permanent(err)
		}
		log.Warn().
			Err(err).
			Int("attempt", attempt).
			Str("operation", operationName).
			Msg("operation failed, retrying")
		return err
	}, bCtx, nil, timer)

	if err != nil {
		return fmt.Errorf("%s failed after %d attempts: %w", operationName, attempt, err)
	}

	if attempt > 1 {
		log.Info().
			Int("attempts", attempt).
			Str("operation", operationName).
			Msg("operation succeeded after retry")
	}

	return nil
}
