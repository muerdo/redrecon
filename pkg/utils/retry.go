package utils

import (
	"context"
	"fmt"
	"time"

	"github.com/cenkalti/backoff/v4"
)

// RetryConfig defines retry behavior
type RetryConfig struct {
	MaxRetries      int
	InitialInterval time.Duration
	MaxInterval     time.Duration
	MaxElapsedTime  time.Duration
	Multiplier      float64
}

// DefaultRetryConfig returns sensible defaults for retries
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      3,
		InitialInterval: 1 * time.Second,
		MaxInterval:     30 * time.Second,
		MaxElapsedTime:  2 * time.Minute,
		Multiplier:      2.0,
	}
}

// CTFRetryConfig returns conservative retry config for CTF (faster, fewer retries)
func CTFRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:      2,
		InitialInterval: 500 * time.Millisecond,
		MaxInterval:     10 * time.Second,
		MaxElapsedTime:  30 * time.Second,
		Multiplier:      1.5,
	}
}

// RetryWithBackoff executes an operation with exponential backoff
func RetryWithBackoff(ctx context.Context, operation func() error, config RetryConfig) error {
	bo := backoff.NewExponentialBackOff()
	bo.InitialInterval = config.InitialInterval
	bo.MaxInterval = config.MaxInterval
	bo.MaxElapsedTime = config.MaxElapsedTime
	bo.Multiplier = config.Multiplier

	attempt := 0

	retryOperation := func() error {
		attempt++

		select {
		case <-ctx.Done():
			return backoff.Permanent(ctx.Err())
		default:
		}

		err := operation()
		if err == nil {
			return nil
		}

		// Check if we've exceeded max retries
		if attempt >= config.MaxRetries {
			return backoff.Permanent(fmt.Errorf("max retries (%d) exceeded: %w", config.MaxRetries, err))
		}

		return err
	}

	return backoff.Retry(retryOperation, backoff.WithContext(bo, ctx))
}

// IsRetryable checks if an error should be retried
func IsRetryable(err error) bool {
	if err == nil {
		return false
	}

	// Add logic to determine if error is retryable
	// For now, retry most errors except context cancellation
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}

	return true
}
