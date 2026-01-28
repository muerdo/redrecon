package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

// RunUncover runs the uncover tool to find exposed assets.
func RunUncover(ctx context.Context, query string, outputFile string, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Uncover
	toolPath := config.GetToolPath("uncover")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("uncover disabled or not found")
	}

	args := []string{
		"-q", query,
		"-o", outputFile,
		"-silent",
	}

	// Add configured engines if any
	if len(t.Engines) > 0 {
		args = append(args, "-e", strings.Join(t.Engines, ","))
	}

	// Add limit if configured
	if t.Limit > 0 {
		args = append(args, "-l", fmt.Sprintf("%d", t.Limit))
	}

	args = append(args, t.ExtraArgs...)

	logger.Info("Running Uncover", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}
