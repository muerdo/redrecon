package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunSubzy(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Subzy
	toolPath := config.GetToolPath("subzy")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("subzy disabled or not found")
	}

	args := []string{
		"run",
		"--targets", inputFile,
		"--output", outputFile,
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Subzy", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}