package utils

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestConcurrencyLimiter_Basic(t *testing.T) {
	limiter := NewConcurrencyLimiter(2)

	if limiter.GetLimit() != 2 {
		t.Errorf("Expected limit 2, got %d", limiter.GetLimit())
	}

	ctx := context.Background()

	// Acquire first slot
	if err := limiter.Acquire(ctx); err != nil {
		t.Fatalf("Failed to acquire first slot: %v", err)
	}

	if limiter.GetActive() != 1 {
		t.Errorf("Expected 1 active, got %d", limiter.GetActive())
	}

	// Acquire second slot
	if err := limiter.Acquire(ctx); err != nil {
		t.Fatalf("Failed to acquire second slot: %v", err)
	}

	if limiter.GetActive() != 2 {
		t.Errorf("Expected 2 active, got %d", limiter.GetActive())
	}

	// Release slots
	limiter.Release()
	limiter.Release()

	if limiter.GetActive() != 0 {
		t.Errorf("Expected 0 active after release, got %d", limiter.GetActive())
	}
}

func TestConcurrencyLimiter_ContextCancellation(t *testing.T) {
	limiter := NewConcurrencyLimiter(1)
	ctx, cancel := context.WithCancel(context.Background())

	// Acquire the only slot
	if err := limiter.Acquire(ctx); err != nil {
		t.Fatalf("Failed to acquire slot: %v", err)
	}

	// Cancel context
	cancel()

	// Try to acquire with cancelled context
	err := limiter.Acquire(ctx)
	if err == nil {
		t.Error("Expected error with cancelled context")
	}

	limiter.Release()
}

func TestConcurrencyLimiter_RunWithLimit(t *testing.T) {
	limiter := NewConcurrencyLimiter(2)
	ctx := context.Background()

	executed := false
	err := limiter.RunWithLimit(ctx, func() error {
		executed = true
		return nil
	})

	if err != nil {
		t.Errorf("RunWithLimit failed: %v", err)
	}

	if !executed {
		t.Error("Function was not executed")
	}

	if limiter.GetActive() != 0 {
		t.Errorf("Expected 0 active after RunWithLimit, got %d", limiter.GetActive())
	}
}

func TestRetryWithBackoff_Success(t *testing.T) {
	ctx := context.Background()
	config := CTFRetryConfig()

	attempts := 0
	operation := func() error {
		attempts++
		if attempts < 2 {
			return fmt.Errorf("temporary error")
		}
		return nil
	}

	err := RetryWithBackoff(ctx, operation, config)
	if err != nil {
		t.Errorf("Expected success after retries, got: %v", err)
	}

	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", attempts)
	}
}

func TestRetryWithBackoff_MaxRetries(t *testing.T) {
	ctx := context.Background()
	config := CTFRetryConfig()
	config.MaxRetries = 2

	attempts := 0
	operation := func() error {
		attempts++
		return fmt.Errorf("persistent error")
	}

	err := RetryWithBackoff(ctx, operation, config)
	if err == nil {
		t.Error("Expected error after max retries")
	}

	if attempts != 2 {
		t.Errorf("Expected 2 attempts (max retries), got %d", attempts)
	}
}

func TestRetryWithBackoff_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	config := DefaultRetryConfig()

	operation := func() error {
		time.Sleep(200 * time.Millisecond)
		return fmt.Errorf("slow operation")
	}

	err := RetryWithBackoff(ctx, operation, config)
	if err == nil {
		t.Error("Expected context cancellation error")
	}
}
