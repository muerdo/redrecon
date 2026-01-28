package tools

import (
	"context"
	"log/slog"
	"path/filepath"

	"redrecon/pkg/utils"
)

func RunCloudenum(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	toolName := "cloudenum"
	if !utils.CommandExists(toolName) {
		logger.Warn("cloudenum not found, skipping cloud enumeration.", "help", "Install from: https://github.com/initstring/cloud_enum")
		return nil
	}
	logger.Info("Executing external command: cloudenum", "target", target)
	args := []string{
		"-k", target,
		"-j", outputFile,
		"-l", filepath.Join(filepath.Dir(outputFile), "cloudenum.log"),
	}
	_, err := utils.ExecuteCommand(ctx, logger, toolName, args...)
	return err
}