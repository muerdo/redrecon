package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

// RunNuclei executa o Nuclei com templates e parâmetros configurados.
func RunNuclei(ctx context.Context, input string, tags string, proxy string, headers []string, cookies, username, password string, logger *slog.Logger, extraArgs []string) (string, error) {

	n := config.Cfg.Tools.Nuclei
	// DEBUG: Print viper settings
	// slog.Info("DEBUG: Viper All Settings", "settings", viper.AllSettings())
	// slog.Info("DEBUG: Viper Nuclei Templates", "templates", viper.Get("tools.nuclei.templates"))
	// We need to import viper in this file if we want to use it, but it's in internal/config.
	// Instead, let's just trust that if viper.Get works, unmarshal should work.
	// But since I can't easily import viper here without adding dependency, I'll assume config.Cfg is the source of truth.
	// Wait, I can import viper.

	logger.Info("DEBUG: Nuclei Config Loaded", "templates", n.Templates, "owasp", n.OWASPTemplates, "monitor", n.MonitorTemplates, "tags", tags)

	if !utils.CommandExists("nuclei") {
		return "", fmt.Errorf("nuclei binary not found in PATH")
	}

	outputDir := filepath.Join(filepath.Dir(input), "nuclei_output") // Assuming input is a file in the target directory
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory %s for nuclei: %w", outputDir, err)
	}
	nucleiOutputFile := filepath.Join(outputDir, "nuclei_findings.jsonl")

	// Validate that templates are provided
	if len(n.Templates) == 0 && len(n.OWASPTemplates) == 0 && len(n.MonitorTemplates) == 0 && tags == "" {
		return "", fmt.Errorf("nuclei requires at least one template or template tag to be configured")
	}

	// Monta args CLI
	args := []string{
		"-l", input, // Lista de targets
		"-o", nucleiOutputFile, // Output
		"-update-templates", // Always update templates
	}

	if n.Silent {
		args = append(args, "-silent")
	}
	if n.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", n.Timeout))
	}
	if n.RateLimit > 0 {
		args = append(args, "-rl", fmt.Sprintf("%d", n.RateLimit))
	}
	if n.Concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", n.Concurrency))
	}

	// Templates from config
	for _, t := range n.Templates {
		args = append(args, "-t", t)
	}

	// Templates from OWASP config
	for _, t := range n.OWASPTemplates {
		args = append(args, "-t", t)
	}

	// Templates from Monitor config
	for _, t := range n.MonitorTemplates {
		args = append(args, "-t", t)
	}

	// Templates from tags
	if tags != "" {
		args = append(args, "-tags", tags)
	}

	if proxy != "" {
		args = append(args, "-proxy", proxy)
	}

	// Headers
	for _, h := range headers {
		args = append(args, "-H", h)
	}

	// Cookies
	if cookies != "" {
		args = append(args, "-cookie", cookies)
	}

	// Basic Auth
	// Nuclei doesn't have a direct flag for basic auth username/password in the same way as some other tools,
	// but it supports headers. We can construct the Authorization header.
	if username != "" && password != "" {
		// However, Nuclei *does* have -H for headers.
		// Let's use the helper to create the header value.
		// But wait, Nuclei might handle this differently if we want to fuzz auth.
		// For now, let's assume we just want to be authenticated.
		// Actually, checking Nuclei docs/help, it doesn't seem to have -u/-p for target auth globally,
		// it usually relies on templates or headers.
		// Let's add it as a header.
		authHeader := utils.BasicAuthHeader(username, password)
		args = append(args, "-H", authHeader)
	}

	// Modos
	if n.Aggressive {
		args = append(args, "-a") // Aggressive mode
	}
	if n.Headless {
		args = append(args, "-headless")
	}
	if n.JSONOutput {
		args = append(args, "-jsonl") // JSON lines para parsing
	}

	// Extra args
	args = append(args, extraArgs...)

	// Interactsh configuration
	if n.InteractshURL != "" {
		args = append(args, "-interactsh-url", n.InteractshURL)
	}
	if n.InteractshToken != "" {
		args = append(args, "-interactsh-token", n.InteractshToken)
	}

	toolPath := config.GetToolPath("nuclei")
	if toolPath == "" {
		return "", fmt.Errorf("nuclei not found")
	}

	logger.Info("Running Nuclei", "args", strings.Join(args, " "))
	stdout, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		logger.Warn("Nuclei execution finished with an error. This might be expected.", "error", err, "stdout", stdout)
	}

	if !utils.FileExistsAndIsNotEmpty(nucleiOutputFile) {
		logger.Warn("Nuclei ran but produced no output file, continuing.")
		return nucleiOutputFile, nil
	}

	logger.Info("Nuclei completed", "output", nucleiOutputFile)
	return nucleiOutputFile, nil
}
