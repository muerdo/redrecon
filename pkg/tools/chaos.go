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

func RunChaos(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	t := config.Cfg.Recon.Chaos
	toolPath := config.GetToolPath("chaos")
	if toolPath == "" || !t.Enabled {
		return "", fmt.Errorf("chaos disabled or not found")
	}

	outputFile := filepath.Join(tempDir, "chaos_output.txt")
	args := []string{
		"-d", target,
		"-o", outputFile,
	}
	if t.APIKey != "" {
		args = append(args, "-key", t.APIKey)
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Chaos", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return "", err
	}
	return outputFile, nil
}
