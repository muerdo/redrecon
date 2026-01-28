package recon

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestPipelineManager_RunMonitor(t *testing.T) {
	// Create temp dir and file
	tempDir, err := os.MkdirTemp("", "pipeline_test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	discoveryFile := filepath.Join(tempDir, "subdomains.txt")
	f, err := os.Create(discoveryFile)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	p := &PipelineManager{
		state: &reconState{
			ctx:    ctx,
			logger: logger,
		},
		discoveryFile:  discoveryFile,
		processed:      make(map[string]bool),
		interval:       100 * time.Millisecond,
		newTargetsChan: make(chan string, 100),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		p.RunMonitor()
	}()

	// Simulate data arrival
	time.Sleep(200 * time.Millisecond)
	f, _ = os.OpenFile(discoveryFile, os.O_APPEND|os.O_WRONLY, 0644)
	f.WriteString("sub1.example.com\n")
	f.WriteString("sub2.example.com\n")
	f.Close()

	// Wait for monitor to pick up
	timeout := time.After(2 * time.Second)

	expected := map[string]bool{
		"sub1.example.com": false,
		"sub2.example.com": false,
	}
	received := 0

	for received < 2 {
		select {
		case target := <-p.newTargetsChan:
			if _, ok := expected[target]; ok {
				expected[target] = true
				received++
			} else {
				t.Errorf("Unexpected target: %s", target)
			}
		case <-timeout:
			t.Fatal("Timeout waiting for targets")
		}
	}

	cancel() // Stop monitor
	// wg.Wait() // Monitor loops until context done, so it should exit.
}

func TestPipelineManager_Batcher(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	p := &PipelineManager{
		state: &reconState{
			ctx:    ctx,
			logger: logger,
		},
		newTargetsChan: make(chan string, 100),
		batchesChan:    make(chan []string, 100),
	}

	go p.Batcher()

	// Send 15 targets
	for i := 0; i < 15; i++ {
		p.newTargetsChan <- "target"
	}

	// Expect 1 batch of 10
	select {
	case batch := <-p.batchesChan:
		if len(batch) != 10 {
			t.Errorf("Expected batch size 10, got %d", len(batch))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for first batch")
	}

	// Expect remaining 5 after ticker (10s is too long for test, we need to mock ticker or wait)
	// We can't mock ticker easily without changing code structure.
	// But the Batcher loop has a 10s ticker.
	// We should probably make the ticker interval configurable for testing.
	// Or we just send 20 targets.
	for i := 0; i < 5; i++ {
		p.newTargetsChan <- "target"
	}
	// Total 15+5 = 20. First 10 read. 5 pending + 5 new = 10.
	// Should produce another batch immediately.

	select {
	case batch := <-p.batchesChan:
		if len(batch) != 10 {
			t.Errorf("Expected second batch size 10, got %d", len(batch))
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for second batch")
	}
}
