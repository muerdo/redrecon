package recon

import (
	"context"
	"fmt"
	"path/filepath"
	"redrecon/internal/config"
	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
	"sync"
)

// stepRunVulnTests orchestrates various vulnerability tests using Nuclei, FFUF, and Dalfox.
func stepRunVulnTests(state *reconState) error {
	state.logger.Info("Starting vulnerability tests...")

	var wg sync.WaitGroup
	errs := make(chan error, 10) // Buffer for errors

	targets, err := utils.ReadLines(state.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read live subdomains for vuln tests: %w", err)
	}

	// Nuclei tests - Run ONCE on the file, not per target
	// This fixes the O(N^2) bug where we ran nuclei on the whole file for every target in the loop
	wg.Add(1)
	go func() {
		defer wg.Done()
		var proxy string
		if state.proxyManager != nil {
			proxy = state.proxyManager.GetNextProxy()
		}

		// Use tags from state if available
		tags := state.nucleiTags

		_, err := tools.RunNuclei(state.ctx, state.liveSubdomainsFile, tags, proxy, state.headers, state.cookies, state.username, state.password, state.logger, nil)
		if err != nil {
			errs <- fmt.Errorf("nuclei vuln test failed: %w", err)
		}
	}()

	// Limit concurrency
	maxConcurrency := config.Cfg.Engine.MaxParallelTasks
	if maxConcurrency <= 0 {
		maxConcurrency = 5 // Default fallback
	}
	sem := make(chan struct{}, maxConcurrency)

	for _, t := range targets {
		// FFUF tests (example for XSS/SQLi)
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()

			// Wait for resources before acquiring semaphore
			if gov := utils.GetGovernor(); gov != nil {
				if err := gov.WaitForResources(state.ctx); err != nil {
					state.logger.Warn("Governor wait failed (context canceled)", "error", err)
					return
				}
			}

			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			ffufOutputDir := filepath.Join(state.resultsPath, utils.SanitizeTargetForPath(targetURL), "ffuf_vuln_results")
			// FFUF for XSS/SQLi can use specific wordlists with payloads
			// This assumes the user configures FFUF.ExtraArgs with appropriate payloads and FUZZ keyword
			// For example, a wordlist with XSS payloads and target URL like "http://example.com/search?q=FUZZ"
			// The call to RunFfuf was missing an argument. Adding an empty string for the output file.
			var proxy string
			if state.proxyManager != nil {
				proxy = state.proxyManager.GetNextProxy()
			}
			err := tools.RunFfuf(context.Background(), targetURL, ffufOutputDir, config.Cfg.Wordlists.Fuzzing, "", 0, proxy, state.headers, state.cookies, state.logger)
			if err != nil {
				errs <- fmt.Errorf("ffuf vuln test for %s failed: %w", targetURL, err)
			}
		}(t)

		// Dalfox tests (XSS)
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()

			// Wait for resources before acquiring semaphore
			if gov := utils.GetGovernor(); gov != nil {
				if err := gov.WaitForResources(state.ctx); err != nil {
					state.logger.Warn("Governor wait failed (context canceled)", "error", err)
					return
				}
			}

			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			dalfoxOutputFile := filepath.Join(state.resultsPath, utils.SanitizeTargetForPath(targetURL), "dalfox_vuln_results.json")
			// Dalfox is specifically for XSS
			err := tools.RunDalfox(context.Background(), targetURL, dalfoxOutputFile, state.tempDir, state.logger)
			if err != nil {
				errs <- fmt.Errorf("dalfox vuln test for %s failed: %w", targetURL, err)
			}
		}(t)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		state.logger.Warn("Vulnerability test error (continuing)", "err", err)
	}

	state.logger.Info("Vulnerability tests completed.")
	return nil
}
