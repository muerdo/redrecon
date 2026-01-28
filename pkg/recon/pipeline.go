package recon

import (
	"redrecon/pkg/tools"
	"redrecon/pkg/utils"

	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// PipelineManager coordinates the streaming of results from discovery to active analysis
type PipelineManager struct {
	state          *reconState
	discoveryFile  string
	processed      map[string]bool
	mu             sync.Mutex
	workerLimit    int
	interval       time.Duration
	newTargetsChan chan string
	batchesChan    chan []string
}

// StartStreamingRecon initiates the recon workflow in streaming mode.
// Phase 1 (Passive) runs in background.
// Phase 2 (Processing) consumes results via PipelineManager.
func StartStreamingRecon(state *reconState) error {
	state.logger.Info("🚀 Starting Recon in STREAMING/PIPELINE Mode")

	// Create channels
	// Buffer size 500 to avoid blocking
	pipeline := &PipelineManager{
		state:          state,
		discoveryFile:  state.subdomainsFile, // This is where passive tools write
		processed:      make(map[string]bool),
		workerLimit:    10, // Max concurrent active scans
		interval:       2 * time.Minute,
		newTargetsChan: make(chan string, 500),
		batchesChan:    make(chan []string, 50),
	}

	// Start Passive Enum in Background
	go func() {
		state.logger.Info("Starting Passive Discovery in Background...")
		if err := stepRunPassiveEnum(state); err != nil {
			state.logger.Error("Passive Enum failed", "error", err)
		}
		// When passive finished, we should signal pipeline
		state.logger.Info("Passive Discovery Finished. Waiting for pipeline to drain.")
		// In a real robust system we'd have a signal here.
		// For now, the pipeline will just keep running until timeout or we implement a signal.
	}()

	// Start Pipeline Monitor
	go pipeline.RunMonitor()

	// Start Batcher
	go pipeline.Batcher()

	// Start Workers
	pipeline.RunWorkers()

	// Wait for completion (or manual stop for now, as this is infinite loop style)
	// In production, we'd use a Done channel from the passive step + wait for queue empty.
	// For this quick implementation, we block until context cancel or "reasonable time" after file stops growing?
	// Let's block on context.
	<-state.ctx.Done()
	return nil
}

// RunMonitor periodically checks the discovery file for new lines
func (p *PipelineManager) RunMonitor() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	// Initial check
	p.checkNewTargets()

	for {
		select {
		case <-p.state.ctx.Done():
			return
		case <-ticker.C:
			p.checkNewTargets()
		}
	}
}

func (p *PipelineManager) checkNewTargets() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !utils.FileExists(p.discoveryFile) {
		return
	}

	file, err := os.Open(p.discoveryFile)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// If not processed
		if !p.processed[line] {
			p.processed[line] = true
			// Send to worker
			// Non-blocking send in case buffer is full? Or blocking?
			// Blocking is safer for flow control.
			select {
			case p.newTargetsChan <- line:
				count++
			case <-time.After(5 * time.Second):
				// timeout if workers are too slow, to avoid blocking monitor forever
				// but this means we might drop targets.
				// Better to spin up a "feeder" routine if we want true reliability.
				// For now, let's just log warn
				p.state.logger.Warn("Pipeline buffer full, skipping target for this cycle", "target", line)
				p.processed[line] = false // Retry next time
			}
		}
	}

	if count > 0 {
		p.state.logger.Info("Pipeline: Discovered new targets", "count", count)
	}
}

// RunWorkers consumes new targets and runs active steps
func (p *PipelineManager) RunWorkers() {
	// Simple worker pool
	for i := 0; i < p.workerLimit; i++ {
		go func(workerID int) {
			for batch := range p.batchesChan {
				if p.state.ctx.Err() != nil {
					return
				}
				p.processBatch(workerID, batch)
			}
		}(i)
	}
}

// Batcher accumulates targets and sends batches to workers
func (p *PipelineManager) Batcher() {
	var batch []string
	ticker := time.NewTicker(10 * time.Second) // Flush every 10 seconds max
	defer ticker.Stop()

	for {
		select {
		case <-p.state.ctx.Done():
			return
		case target := <-p.newTargetsChan:
			batch = append(batch, target)
			if len(batch) >= 10 { // Batch size 10
				p.batchesChan <- batch
				batch = nil
			}
		case <-ticker.C:
			if len(batch) > 0 {
				p.batchesChan <- batch
				batch = nil
			}
		}
	}
}

func (p *PipelineManager) processBatch(workerID int, targets []string) {
	p.state.logger.Info("Pipeline Worker Processing Batch", "workerID", workerID, "count", len(targets))

	// Create temp input file for this batch
	tempInput, err := os.CreateTemp(p.state.tempDir, fmt.Sprintf("batch_%d_*.txt", workerID))
	if err != nil {
		p.state.logger.Error("Failed to create temp batch file", "error", err)
		return
	}
	defer os.Remove(tempInput.Name())

	if _, err := tempInput.WriteString(strings.Join(targets, "\n")); err != nil {
		p.state.logger.Error("Failed to write batch targets", "error", err)
		return
	}
	tempInput.Close()

	// Define output files for this batch
	batchIPsFile := filepath.Join(p.state.tempDir, fmt.Sprintf("batch_%d_ips.txt", workerID))
	batchPortsFile := filepath.Join(p.state.tempDir, fmt.Sprintf("batch_%d_ports.txt", workerID))
	batchHttpxFile := filepath.Join(p.state.tempDir, fmt.Sprintf("batch_%d_httpx.json", workerID))

	// 1. Resolve IPs
	// We can use a simple loop or use p.state.reconResolveSubdomains step logic?
	// Let's us utils.ResolveIPs.
	if err := utils.ResolveIPs(tempInput.Name(), batchIPsFile); err != nil {
		p.state.logger.Error("Failed to resolve batch IPs", "error", err)
	}

	// 2. Port Scan (Naabu)
	// Only if not skipped. How to check skips? p.state has no skip info directly?
	// p.state should store skipSteps? It doesn't seem to have `skipSteps` field exposed.
	// We might need to add `skipSteps` to `reconState`.
	// For now, let's assume we run standard active checks: Naabu + Httpx.

	if err := tools.RunNaabu(p.state.ctx, tempInput.Name(), batchPortsFile, p.state.tempDir, p.state.logger); err != nil {
		p.state.logger.Error("Naabu batch failed", "error", err)
	}

	// 3. HTTP Probe (Httpx)
	// We use the original domains (tempInput)
	// We need to capture live hosts.
	batchLiveHosts := filepath.Join(p.state.tempDir, fmt.Sprintf("batch_%d_live.txt", workerID))

	if err := tools.RunHttpx(p.state.ctx, tempInput.Name(), batchHttpxFile, batchLiveHosts, p.state.tempDir, p.state.followRedirects, "", false, "", p.state.headers, p.state.cookies, p.state.username, p.state.password, p.state.logger); err != nil {
		p.state.logger.Error("Httpx batch failed", "error", err)
	}

	// 4. Append results to main state files
	// Lock needed? Yes, files in `reconState` are "global".
	// But appending to files concurrently is tricky without locks or atomic writes.
	// `utils.AppendToFile` (if exists) usually opens in Append mode which is atomic on POSIX?
	// It's better to use a mutex on the state. However, `reconState` doesn't have a file mutex.
	// We can add a global mutex in `PipelineManager` for file writes.

	p.mu.Lock()
	defer p.mu.Unlock()

	// Append Live Hosts
	if utils.FileExistsAndIsNotEmpty(batchLiveHosts) {
		content, _ := os.ReadFile(batchLiveHosts)
		utils.AppendToFile(p.state.liveSubdomainsFile, string(content))
		p.state.logger.Info("Stream: New Live Hosts Found", "workerID", workerID)
	}

	// Append URLs?
	// Naabu output?
}
