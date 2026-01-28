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

func RunCertspotter(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	t := config.Cfg.Recon.Certspotter
	toolPath := config.GetToolPath("certspotter")
	if toolPath == "" || !t.Enabled {
		return "", fmt.Errorf("certspotter disabled or not found")
	}

	outputFile := filepath.Join(tempDir, "certspotter_output.txt")
	args := []string{
		"-d", target,
		"-o", outputFile,
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Certspotter", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return "", err
	}
	return outputFile, nil
}
