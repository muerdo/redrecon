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

func RunAmass(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	t := config.Cfg.Recon.Amass
	toolPath := config.GetToolPath("amass")
	if toolPath == "" || !t.Enabled {
		return "", fmt.Errorf("amass disabled or not found")
	}

	outputFile := filepath.Join(tempDir, "amass_output.txt")
	args := []string{
		"enum",
		"-d", target,
		"-dir", tempDir,
		"-o", outputFile,
	}
	if t.Passive {
		args = append(args, "-passive")
	}
	if t.Timeout > 0 {
		args = append(args, "-timeout", fmt.Sprintf("%d", t.Timeout))
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Amass", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return "", err
	}
	return outputFile, nil
}
