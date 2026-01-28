package utils

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// StepRunner manages the execution of recon steps and handles interruption signals.
type StepRunner struct {
	mainCtx       context.Context
	mainCancel    context.CancelFunc
	currentCancel context.CancelFunc
	mu            sync.Mutex
	logger        *slog.Logger
	sigChan       chan os.Signal
	OnStepStart   func(string)

	// Status tracking
	currentStepName string
	stepStartTime   time.Time
}

// NewStepRunner creates a new StepRunner.
func NewStepRunner(ctx context.Context, logger *slog.Logger) *StepRunner {
	ctx, cancel := context.WithCancel(ctx)
	runner := &StepRunner{
		mainCtx:    ctx,
		mainCancel: cancel,
		logger:     logger,
		sigChan:    make(chan os.Signal, 1),
	}
	runner.StartSignalHandler()
	return runner
}

// SetStatusCallback sets the function to call when a step starts.
func (r *StepRunner) SetStatusCallback(fn func(string)) {
	r.OnStepStart = fn
}

// StartSignalHandler starts listening for SIGINT/SIGTERM.
func (r *StepRunner) StartSignalHandler() {
	signal.Notify(r.sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		lastSignalTime := time.Time{}
		for {
			select {
			case <-r.mainCtx.Done():
				return
			case <-r.sigChan:
				now := time.Now()
				// Double Ctrl+C check (within 2 seconds)
				if now.Sub(lastSignalTime) < 2*time.Second {
					r.logger.Warn("Double Ctrl+C detected. Exiting program...")
					r.mainCancel()
					return
				}
				lastSignalTime = now

				r.mu.Lock()
				if r.currentCancel != nil {
					r.logger.Warn("Ctrl+C detected. Skipping current step...")
					r.currentCancel()
					r.currentCancel = nil // Prevent multiple cancels for same step
				} else {
					r.logger.Info("Ctrl+C detected but no step is running (or already cancelled). Press again to exit.")
				}
				r.mu.Unlock()
			}
		}
	}()
}

// Run executes a step with context management.
func (r *StepRunner) Run(name string, fn func(ctx context.Context) error) error {
	// Check if main context is already done
	if r.mainCtx.Err() != nil {
		return r.mainCtx.Err()
	}

	// Create a context for this step
	stepCtx, cancel := context.WithCancel(r.mainCtx)

	r.mu.Lock()
	r.currentCancel = cancel
	r.currentStepName = name
	r.stepStartTime = time.Now()
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		if r.currentCancel != nil {
			cancel() // Ensure cleanup
			r.currentCancel = nil
		}
		r.currentStepName = "" // Clear status
		r.mu.Unlock()
	}()

	r.logger.Info(fmt.Sprintf("--- Starting Step: %s ---", name))
	if r.OnStepStart != nil {
		r.OnStepStart(name)
	}
	err := fn(stepCtx)

	if stepCtx.Err() == context.Canceled && r.mainCtx.Err() == nil {
		r.logger.Warn(fmt.Sprintf("Step '%s' was skipped by user.", name))
		return nil // Treat skip as success for the workflow flow
	}

	return err
}

// Context returns the main context of the runner.
func (r *StepRunner) Context() context.Context {
	return r.mainCtx
}

// StartInputMonitor starts a goroutine to listen for user input (Enter key)
// to print the current status.
func (r *StepRunner) StartInputMonitor() {
	go func() {
		// Only run if stdin is a terminal
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			return
		}

		buf := make([]byte, 1)
		for {
			if r.mainCtx.Err() != nil {
				return
			}
			// Read single byte (blocking)
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				return
			}

			// If Enter (newline) is pressed
			if buf[0] == '\n' || buf[0] == '?' {
				r.PrintStatus()
			}
		}
	}()
}

// PrintStatus prints the current step and duration to stdout/log.
func (r *StepRunner) PrintStatus() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.currentStepName != "" {
		duration := time.Since(r.stepStartTime).Round(time.Second)
		msg := fmt.Sprintf("\n[STATUS] Current Step: %s | Running for: %s\n", r.currentStepName, duration)
		fmt.Print(msg) // Direct to stdout for user visibility
		// r.logger.Info("Status check", "step", r.currentStepName, "duration", duration)
	} else {
		fmt.Println("\n[STATUS] Idle / No active step.")
	}
}
