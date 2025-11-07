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

func RunGau(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	t := config.Cfg.Recon.Gau
	toolPath := config.GetToolPath("gau")
	if toolPath == "" || !t.Enabled {
		return "", fmt.Errorf("gau disabled or not found")
	}

	outputFile := filepath.Join(tempDir, "gau_output.txt")
	args := []string{
		target,
	}
	args = append(args, t.ExtraArgs...)

	output, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return "", err
	}
	os.WriteFile(outputFile, []byte(output), 0644)
	return outputFile, nil
}