
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

func RunDalfox(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Dalfox
	toolPath := config.GetToolPath("dalfox")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("dalfox disabled or not found")
	}

	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		return fmt.Errorf("failed to create output directory for dalfox: %w", err)
	}

	profile, ok := utils.GetActiveWAFProfile(logger, "", tempDir)
	proxy := t.Proxy
	// If no specific proxy is set for the tool, try to use one from the WAF profile.
	if proxy == "" && ok && len(profile.Proxies) > 0 {
		proxy = profile.Proxies[0] // Use the first proxy from the profile list
		logger.Debug("Using WAF profile proxy for Dalfox", "proxy", proxy)
	}

	args := []string{
		"file", inputFile,
		"-o", outputFile,
	}
	if proxy != "" {
		args = append(args, "--proxy", proxy)
	}
	args = append(args, t.ExtraArgs...)

	// Interactsh configuration
	if config.Cfg.Tools.Dalfox.InteractshURL != "" {
		args = append(args, "--oob", "--ooB-url", config.Cfg.Tools.Dalfox.InteractshURL)
		if config.Cfg.Tools.Dalfox.InteractshToken != "" {
			args = append(args, "--oob-token", config.Cfg.Tools.Dalfox.InteractshToken)
		}
	}

	logger.Info("Running Dalfox", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}
