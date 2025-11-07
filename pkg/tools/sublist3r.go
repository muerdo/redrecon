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

func RunSublist3r(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	t := config.Cfg.Recon.Sublist3r
	toolPath := config.GetToolPath("sublist3r")
	if toolPath == "" || !t.Enabled {
		return "", fmt.Errorf("sublist3r disabled or not found")
	}

	outputFile := filepath.Join(tempDir, "sublist3r_output.txt")
	args := []string{
		"-d", target,
	}
	if t.Threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", t.Threads))
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Sublist3r", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return "", err
	}
	return outputFile, nil
}
