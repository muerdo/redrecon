package tools

import (
	"context"
	"log/slog"
	"os"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)
func RunSipScan(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	output, err := utils.ExecuteCommand(ctx, logger, config.GetToolPath("svmap"), target)
	if err == nil && output != "" {
		os.WriteFile(outputFile, []byte(output), 0644)
	}
	return err
}
