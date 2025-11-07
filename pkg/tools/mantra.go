
// pkg/tools/mantra.go
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

// RunMantra executes the mantra tool to find secrets in API endpoints.
func RunMantra(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	bin := config.GetToolPath("mantra")
	if bin == "mantra" {
		return fmt.Errorf("Mantra not found. Check tool_paths.mantra in config.yaml")
	}

	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		return fmt.Errorf("failed to create output directory for mantra: %w", err)
	}

	args := []string{
		"-f", inputFile,
		"-o", outputFile,
	}

	_, err := utils.ExecuteCommand(ctx, logger, bin, args...)
	return err
}
