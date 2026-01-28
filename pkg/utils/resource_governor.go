package utils

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/mem"
)

// ResourceGovernor manages task execution based on system resource usage.
type ResourceGovernor struct {
	mu            sync.Mutex
	cpuThreshold  float64
	ramThreshold  float64
	checkInterval time.Duration
	logger        *slog.Logger
	enabled       bool
}

var (
	globalGovernor *ResourceGovernor
	once           sync.Once
)

// InitResourceGovernor initializes the global resource governor.
func InitResourceGovernor(cpuThreshold, ramThreshold float64, checkInterval string, logger *slog.Logger) error {
	var err error
	once.Do(func() {
		interval, parseErr := time.ParseDuration(checkInterval)
		if parseErr != nil {
			interval = 5 * time.Second // Default
			if logger != nil {
				logger.Warn("Invalid check interval for resource governor, using default", "error", parseErr)
			}
		}

		if cpuThreshold <= 0 {
			cpuThreshold = 60.0 // Default 60% as requested
		}
		if ramThreshold <= 0 {
			ramThreshold = 60.0 // Default 60% as requested
		}

		globalGovernor = &ResourceGovernor{
			cpuThreshold:  cpuThreshold,
			ramThreshold:  ramThreshold,
			checkInterval: interval,
			logger:        logger,
			enabled:       true,
		}
		if logger != nil {
			logger.Info("Resource Governor initialized", "cpu_limit", cpuThreshold, "ram_limit", ramThreshold, "interval", interval)
		}
	})
	return err
}

// GetGovernor returns the global governor instance.
func GetGovernor() *ResourceGovernor {
	return globalGovernor
}

// WaitForResources blocks the caller until system resources are below the configured thresholds.
// It checks periodically based on CheckInterval.
func (rg *ResourceGovernor) WaitForResources(ctx context.Context) error {
	if rg == nil || !rg.enabled {
		return nil
	}

	ticker := time.NewTicker(rg.checkInterval)
	defer ticker.Stop()

	// Initial check to avoid waiting if everything is fine
	if err := rg.checkResources(); err == nil {
		return nil
	}

	rg.logger.Warn("System resources exceeded thresholds. Pausing execution until resources free up...",
		"cpu_limit", rg.cpuThreshold, "ram_limit", rg.ramThreshold)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := rg.checkResources(); err == nil {
				rg.logger.Info("Resources stabilized. Resuming execution.")
				return nil
			}
			// Optional: log debug heartbeat "Still waiting for resources..."
		}
	}
}

func (rg *ResourceGovernor) checkResources() error {
	// Check Memory
	v, err := mem.VirtualMemory()
	if err != nil {
		rg.logger.Error("Failed to get memory stats", "error", err)
		return nil // Fail open if we can't check
	}

	if v.UsedPercent > rg.ramThreshold {
		return fmt.Errorf("memory usage too high: %.2f%% (limit: %.2f%%)", v.UsedPercent, rg.ramThreshold)
	}

	// Check CPU
	// cpu.Percent takes a duration for sampling. If 0, it uses the time since last call.
	// We use a small window for the check.
	cpuPers, err := cpu.Percent(500*time.Millisecond, false)
	if err != nil {
		rg.logger.Error("Failed to get CPU stats", "error", err)
		return nil // Fail open
	}

	// cpuPers is a slice (one per core if percpu=true, or just one total). We used false.
	if len(cpuPers) > 0 && cpuPers[0] > rg.cpuThreshold {
		return fmt.Errorf("cpu usage too high: %.2f%% (limit: %.2f%%)", cpuPers[0], rg.cpuThreshold)
	}

	return nil
}

// MonitorSystemResources is a helper that logs resource usage periodically (can be run in a goroutine).
func (rg *ResourceGovernor) MonitorSystemResources(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			// This logs Go's *internal* memory usage, which is different from system usage.
			// Currently the governor checks *system* usage.
			// Use logging here if needed.
		}
	}
}
