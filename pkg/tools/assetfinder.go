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

func RunAssetfinder(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	t := config.Cfg.Tools.Assetfinder // FIX: Aponta para a configuração centralizada em 'Tools'.
	toolPath := config.GetToolPath("assetfinder")
	if toolPath == "" || !t.Enabled {
		return "", fmt.Errorf("assetfinder disabled or not found")
	}

	outputFile := filepath.Join(tempDir, "assetfinder_output.txt")
	args := []string{
		"--subs-only", target,
	}
	args = append(args, t.ExtraArgs...)

	output, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return "", err
	}
	os.WriteFile(outputFile, []byte(output), 0644)
	return outputFile, nil
}
