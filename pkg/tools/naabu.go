package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

// RunNaabu runs the naabu port scanner.
func RunNaabu(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Naabu
	toolPath := config.GetToolPath("naabu")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("naabu disabled or not found")
	}

	args := append([]string{"-list", inputFile, "-o", outputFile, "-silent"}, t.ExtraArgs...)
	logger.Info("Running Naabu", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}