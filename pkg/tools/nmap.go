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

func RunNmap(ctx context.Context, target, outputFile string, logger *slog.Logger, args ...string) error {
	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for nmap: %w", err)
	}

	fullArgs := []string{}
	isRoot := os.Getuid() == 0

	// Check if -sU is requested and user is not root
	useUDP := false
	for _, arg := range args {
		if arg == "-sU" {
			useUDP = true
			break
		}
	}

	if useUDP && !isRoot {
		logger.Warn("Nmap UDP scan (-sU) requires root privileges. Falling back to TCP scan (-sT) or skipping UDP.", "target", target)
		// We filter out -sU
		for _, arg := range args {
			if arg != "-sU" {
				fullArgs = append(fullArgs, arg)
			}
		}
		// Optionally add -sT if no other scan type is specified, but usually nmap defaults to -sS (root) or -sT (user)
		// If we are not root, -sS also fails/fallbacks.
	} else {
		fullArgs = append(fullArgs, args...)
	}

	// Check if target is a file for -iL usage
	if utils.FileExistsAndIsNotEmpty(target) {
		fullArgs = append(fullArgs, "-iL", target, "-oX", outputFile)
	} else {
		fullArgs = append(fullArgs, "-oX", outputFile, target)
	}

	logger.Info("Executing Nmap", "args", strings.Join(fullArgs, " "))
	_, err := utils.ExecuteCommand(ctx, logger, config.GetToolPath("nmap"), fullArgs...)
	return err
}
