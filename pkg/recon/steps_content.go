package recon

import (
	"fmt"
	"os"
	"path/filepath"
	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

// stepDownloadSiteContent downloads the full site content (mirror) using wget.
func stepDownloadSiteContent(state *reconState) error {
	state.logger.Info("--- Starting: Site Content Download (Mirror) ---")

	if !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Warn("Live subdomains file is empty, skipping content download.")
		return nil
	}

	// Create a directory for the mirrored content
	mirrorDir := filepath.Join(state.resultsPath, "content_mirror")
	if err := os.MkdirAll(mirrorDir, 0755); err != nil {
		return fmt.Errorf("failed to create mirror directory: %w", err)
	}

	targets, err := utils.ReadLines(state.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read live subdomains: %w", err)
	}

	// We can run this in parallel for multiple targets, but let's be careful with bandwidth/rate limits.
	// For now, sequential or limited concurrency.
	for _, targetURL := range targets {
		if state.ctx.Err() != nil {
			return state.ctx.Err()
		}

		targetDomain := utils.ExtractDomain(targetURL)
		targetDir := filepath.Join(mirrorDir, targetDomain)
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			state.logger.Error("Failed to create target mirror dir", "target", targetURL, "error", err)
			continue
		}

		state.logger.Info("Mirroring content for target", "target", targetURL)

		// wget --mirror --convert-links --adjust-extension --page-requisites --no-parent -P <output_dir> <target>
		// Adding --random-wait and user-agent for basic evasion
		args := []string{
			"--mirror",
			"--convert-links",
			"--adjust-extension",
			"--page-requisites",
			"--no-parent",
			"-P", targetDir,
			targetURL,
			"--no-check-certificate", // Often needed for internal/recon targets
			"--timeout=10",
			"--tries=2",
		}

		// Proxy support for wget
		// wget uses http_proxy/https_proxy env vars or -e http_proxy=...
		if state.proxyManager != nil {
			proxy := state.proxyManager.GetNextProxy()
			if proxy != "" {
				args = append(args, "-e", "http_proxy="+proxy)
				args = append(args, "-e", "https_proxy="+proxy)
			}
		}

		// User Agent
		ua := getRandomUserAgent()
		args = append(args, "-U", ua)

		_, err := utils.ExecuteCommand(state.ctx, state.logger, "wget", args...)
		if err != nil {
			state.logger.Warn("wget failed for target (continuing)", "target", targetURL, "error", err)
		}
	}

	state.logger.Info("Site content download completed.")
	return nil
}

// stepRunStaticAnalysis runs semgrep on the downloaded content.
func stepRunStaticAnalysis(state *reconState) error {
	state.logger.Info("--- Starting: Static Analysis (Semgrep) ---")

	mirrorDir := filepath.Join(state.resultsPath, "content_mirror")
	if _, err := os.Stat(mirrorDir); os.IsNotExist(err) {
		state.logger.Warn("Content mirror directory not found, skipping static analysis.", "dir", mirrorDir)
		return nil
	}

	outputFile := filepath.Join(state.resultsPath, "static_analysis.json")

	// Semgrep runs recursively on the directory
	err := tools.RunSemgrep(state.ctx, mirrorDir, outputFile, state.logger)
	if err != nil {
		return fmt.Errorf("semgrep analysis failed: %w", err)
	}

	state.logger.Info("Static analysis completed.", "output", outputFile)
	return nil
}
