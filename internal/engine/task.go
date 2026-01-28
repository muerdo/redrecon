package engine

import "context"

// Task represents a unit of work to be executed by the engine.
type Task interface {
	// Execute runs the task.
	// ctx can be used to signal cancellation.
	Execute(ctx context.Context)

	// ID returns the unique identifier of the task.
	ID() string

	// Description returns a human-readable description of the task.
	Description() string
}
