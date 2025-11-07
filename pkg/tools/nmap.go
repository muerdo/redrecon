package tools

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"os"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunNmap(ctx context.Context, target, outputFile string, logger *slog.Logger, args ...string) error {
	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for nmap: %w", err)
	}

	fullArgs := []string{}
	isRoot := os.Getuid() == 0

	for _, arg := range args {
		if arg == "-sU" && !isRoot {
			logger.Warn("Nmap UDP scan (-sU) requires root privileges. Falling back to TCP scan (-sT).", "target", target)
			fullArgs = append(fullArgs, "-sT")
		} else {
			fullArgs = append(fullArgs, arg)
		}
	}

	fullArgs = append(fullArgs, "-oX", outputFile, target)
	_, err := utils.ExecuteCommand(ctx, logger, config.GetToolPath("nmap"), fullArgs...)
	return err
}
