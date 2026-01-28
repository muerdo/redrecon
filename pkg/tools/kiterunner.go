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

func RunKiterunner(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	t := config.Cfg.Recon.Kiterunner
	toolPath := config.GetToolPath("kiterunner")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("kiterunner disabled or not found")
	}

	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for kiterunner: %w", err)
	}

	args := []string{
		"scan",
		"-l", inputFile,
		"-o", outputFile,
	}
	// FIX: Removido o argumento "-H Host: FUZZ" pois não é necessário para o kiterunner.
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Kiterunner", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}
