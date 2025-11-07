// pkg/tools/bbot.go
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

// RunBBot executes the bbot tool with the specified parameters.
func RunBBot(
	ctx context.Context,
	inputFile, subdomainsFile, outDir string,
	aggressive bool,
	rateLimit, concurrency int,
	proxyFile string,
	logger *slog.Logger,
	extra ...string,
) (string, error) {

	bin := config.GetToolPath("bbot")
	if bin == "bbot" {
		return "", fmt.Errorf("BBOT not found. Check tool_paths.bbot in config.yaml")
	}

	bbotConfig := config.Cfg.Recon.BBot

	// If ListModules is true, list modules and log them
	if bbotConfig.ListModules {
		logger.Info("Listing BBOT modules...")
		modules, err := ListBBotModules(ctx, logger)
		if err != nil {
			logger.Error("Failed to list BBOT modules", "error", err)
		} else {
			logger.Info("Available BBOT modules:", "modules", strings.Join(modules, ", "))
		}
	}

	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory for bbot: %w", err)
	}

	args := []string{
		"-t", inputFile,
		"-o", outDir,
		"-y",
	}

	args = append(args, "--output-module", "ndjson")
	args = append(args, "--output-module", "txt")

    if utils.FileExistsAndIsNotEmpty(subdomainsFile) {
        args = append(args, "-t", "@"+subdomainsFile)
    }

	// Add modules from config, or default modules if none specified
	modulesToRun := bbotConfig.Modules
	if len(modulesToRun) == 0 {
		modulesToRun = config.DefaultBBotModules
	}
	if len(modulesToRun) > 0 {
		args = append(args, "-m", strings.Join(modulesToRun, ","))
	}

	if aggressive {
		args = append(args, "--allow-deadly")
	}
	if proxyFile != "" {
		args = append(args, "--proxy-file", proxyFile)
	}
	if rateLimit > 0 {
		args = append(args, "-c", fmt.Sprintf("http.rate_limit=%d", rateLimit))
	}
	if concurrency > 0 {
		args = append(args, "-c", fmt.Sprintf("concurrency=%d", concurrency))
	}
	args = append(args, extra...)

	_, err := utils.ExecuteCommand(ctx, logger, bin, args...)
	if err != nil {
		return "", err
	}

	jsonFile := filepath.Join(outDir, "output.ndjson")
	if !utils.FileExistsAndIsNotEmpty(jsonFile) {
		matches, _ := filepath.Glob(filepath.Join(outDir, "*.ndjson"))
		if len(matches) > 0 {
			jsonFile = matches[0]
		} else {
			logger.Warn("BBOT ran but output file was not found", "expected_file", jsonFile)
			return "", nil
		}
	}
	logger.Info("BBOT JSON", "file", jsonFile, "lines", utils.CountLines(jsonFile))
	return jsonFile, nil
}

// ListBBotModules lists all available bbot modules.
func ListBBotModules(ctx context.Context, logger *slog.Logger) ([]string, error) {
	bin := config.GetToolPath("bbot")
	if bin == "bbot" {
		return nil, fmt.Errorf("BBOT not found. Check tool_paths.bbot in config.yaml")
	}

	args := []string{"--list-modules"}

	out, err := utils.ExecuteCommand(ctx, logger, bin, args...)
	if err != nil {
		return nil, err
	}

	return strings.Split(out, "\n"), nil
}
