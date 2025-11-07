package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunArjun(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Arjun
	toolPath := config.GetToolPath("arjun")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("arjun disabled or not found")
	}

	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		return fmt.Errorf("failed to create output directory for arjun: %w", err)
	}

	args := []string{
		"-i", inputFile,
		"-oJ", outputFile,
	}
	args = append(args, t.ExtraArgs...)

	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}