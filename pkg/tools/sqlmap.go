package tools

import (
	"context"
	"fmt"
	"os"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunSqlmap(ctx context.Context, inputFile, outputDir, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Sqlmap
	if !t.Enabled {
		logger.Info("sqlmap is disabled in config, skipping.")
		return nil
	}
	toolPath := config.GetToolPath("sqlmap")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("sqlmap disabled or not found")
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for sqlmap: %w", err)
	}

	args := []string{
		"-m", inputFile,
		"--batch",
		"--level", fmt.Sprintf("%d", t.Level),
		"--risk", fmt.Sprintf("%d", t.Risk),
	}

	if t.Proxy != "" {
		args = append(args, "--proxy", t.Proxy)
	} else if config.Cfg.Engine.WAF.Enabled {
		defaultProfileName := config.Cfg.Engine.WAF.DefaultProfile
		if profile, ok := config.Cfg.Engine.WAF.Profiles[defaultProfileName]; ok {
			if profile.Proxy != "" {
				args = append(args, "--proxy", profile.Proxy)
				logger.Debug("Using WAF profile proxy for Sqlmap", "proxy", profile.Proxy)
			}
		}
	}

	args = append(args, t.ExtraArgs...)

	logger.Info("Running Sqlmap", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return fmt.Errorf("sqlmap execution failed: %w", err)
	}
	return nil
}
