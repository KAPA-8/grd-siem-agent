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
}

// DefaultRetryConfig returns sensible defaults for retry behavior.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		InitialInterval: 1 * time.Second,
		MaxInterval:     5 * time.Minute,
		MaxElapsedTime:  30 * time.Minute,
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
	b := backoff.NewExponentialBackOff()
	b.InitialInterval = cfg.InitialInterval
	b.MaxInterval = cfg.MaxInterval
	b.MaxElapsedTime = cfg.MaxElapsedTime
	b.Multiplier = 2

	bCtx := backoff.WithContext(b, ctx)

	attempt := 0
	err := backoff.Retry(func() error {
		attempt++
		err := operation()
		if err == nil {
			return nil
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
	}, bCtx)

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
