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

func RunCVESearch(ctx context.Context, techFile, outputFile string, logger *slog.Logger) error {
	t := config.Cfg.Tools.CVESearch
	toolPath := config.GetToolPath("cve_search")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("cve_search disabled or not found")
	}

	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		return fmt.Errorf("failed to create output directory for cve_search: %w", err)
	}

	args := []string{
		"-f", techFile,
		"-o", outputFile,
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running CVESearch", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}