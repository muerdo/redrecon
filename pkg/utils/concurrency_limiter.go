package utils

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ConcurrencyLimiter controls the number of concurrent operations
type ConcurrencyLimiter struct {
	semaphore chan struct{}
	active    int
	mu        sync.Mutex
	maxLimit  int
}

// NewConcurrencyLimiter creates a new limiter with specified max concurrent operations
func NewConcurrencyLimiter(maxConcurrent int) *ConcurrencyLimiter {
	if maxConcurrent <= 0 {
		maxConcurrent = 1
	}

	return &ConcurrencyLimiter{
		semaphore: make(chan struct{}, maxConcurrent),
		maxLimit:  maxConcurrent,
	}
}

// Acquire blocks until a slot is available or context is cancelled
func (cl *ConcurrencyLimiter) Acquire(ctx context.Context) error {
	select {
	case cl.semaphore <- struct{}{}:
		cl.mu.Lock()
		cl.active++
		cl.mu.Unlock()
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release frees up a slot for another operation
func (cl *ConcurrencyLimiter) Release() {
	cl.mu.Lock()
	cl.active--
	cl.mu.Unlock()

	<-cl.semaphore
}

// GetActive returns the current number of active operations
func (cl *ConcurrencyLimiter) GetActive() int {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.active
}

// GetLimit returns the maximum concurrent operations allowed
func (cl *ConcurrencyLimiter) GetLimit() int {
	return cl.maxLimit
}

// Wait blocks until all active operations complete or timeout
func (cl *ConcurrencyLimiter) Wait(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for {
		cl.mu.Lock()
		active := cl.active
		cl.mu.Unlock()

		if active == 0 {
			return nil
		}

		if time.Now().After(deadline) {
			return fmt.Errorf("timeout waiting for %d operations to complete", active)
		}

		time.Sleep(100 * time.Millisecond)
	}
}

// RunWithLimit executes a function with concurrency limiting
func (cl *ConcurrencyLimiter) RunWithLimit(ctx context.Context, fn func() error) error {
	if err := cl.Acquire(ctx); err != nil {
		return fmt.Errorf("failed to acquire limiter slot: %w", err)
	}
	defer cl.Release()

	return fn()
}
