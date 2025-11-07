package tools

import (
	"context"
	"log/slog"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

// RunEnum4linux runs enum4linux-ng.
func RunEnum4linux(ctx context.Context, target, outputFile string, flags []string, logger *slog.Logger) error {
	args := append([]string{"-A", "-o", outputFile, target}, flags...)
	_, err := utils.ExecuteCommand(ctx, logger, config.GetToolPath("enum4linux-ng"), args...)
	return err
}