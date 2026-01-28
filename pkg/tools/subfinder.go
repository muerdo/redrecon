package tools

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunSubfinder(ctx context.Context, target, tempDir, proxy string, logger *slog.Logger) (string, error) {
	t := config.Cfg.Tools.Subfinder
	toolPath := config.GetToolPath("subfinder")
	if toolPath == "" || !t.Enabled {
		return "", fmt.Errorf("subfinder disabled or not found")
	}

	outputFile := filepath.Join(tempDir, "subfinder_output.txt")
	args := []string{
		"-d", target,
		"-o", outputFile,
		"-silent",
	}
	if t.All {
		args = append(args, "-all")
	}
	if t.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", t.Threads))
	}

	// Use proxy from config and log it for audit
	// Use passed proxy or config proxy
	if proxy != "" {
		args = append(args, "-proxy", proxy)
		utils.LogProxyUsage(logger, "subfinder", proxy)
	} else if t.Proxy != "" {
		args = append(args, "-proxy", t.Proxy)
		utils.LogProxyUsage(logger, "subfinder", t.Proxy)
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Subfinder", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return "", err
	}
	return outputFile, nil
}
