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

	for _, t := range targets {
		// Nuclei tests
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()
			// For OWASP Top 10, we can use specific Nuclei templates or tags
			// Assuming config.Cfg.Recon.Nuclei.OWASPTemplates is populated with relevant templates
			_, err := tools.RunNuclei(context.Background(), targetURL, "owasp", "", state.logger, nil)
			if err != nil {
				errs <- fmt.Errorf("nuclei vuln test for %s failed: %w", targetURL, err)
			}
		}(t)

		// FFUF tests (example for XSS/SQLi)
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()
			ffufOutputDir := filepath.Join(state.resultsPath, utils.SanitizeTargetForPath(targetURL), "ffuf_vuln_results")
			// FFUF for XSS/SQLi can use specific wordlists with payloads
			// This assumes the user configures FFUF.ExtraArgs with appropriate payloads and FUZZ keyword
			// For example, a wordlist with XSS payloads and target URL like "http://example.com/search?q=FUZZ"
			// The call to RunFfuf was missing an argument. Adding an empty string for the output file.
			err := tools.RunFfuf(context.Background(), targetURL, config.Cfg.Wordlists.Fuzzing, ffufOutputDir, "", 0, state.logger)
			if err != nil {
				errs <- fmt.Errorf("ffuf vuln test for %s failed: %w", targetURL, err)
			}
		}(t)

		// Dalfox tests (XSS)
		wg.Add(1)
		go func(targetURL string) {
			defer wg.Done()
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
