package transport

import (
	"context"
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

// WithRetry wraps an operation with exponential backoff retry logic.
// The operation function should return nil on success.
// It will NOT retry on context cancellation.
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
		if err != nil {
			log.Warn().
				Err(err).
				Int("attempt", attempt).
				Str("operation", operationName).
				Msg("operation failed, retrying")
			return err
		}
		return nil
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
