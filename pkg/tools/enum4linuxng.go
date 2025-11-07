package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"path/filepath"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

// RunEnum4linuxNG executa o enum4linux-ng para enumeração SMB/Windows.
func RunEnum4linuxNG(ctx context.Context, target, outputDir, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Enum4linuxNG
	if !t.Enabled {
		logger.Info("enum4linux-ng is disabled in config, skipping.")
		return nil
	}
	toolPath := config.GetToolPath("enum4linux-ng")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("enum4linux-ng disabled or not found")
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for enum4linux-ng: %w", err)
	}

	outputFile := filepath.Join(outputDir, utils.SanitizeTargetForPath(target)+"_enum4linuxng.txt")

	args := []string{
		"-t", target,
		"-o", outputFile,
	}

	if t.Domain != "" {
		args = append(args, "-d", t.Domain)
	}
	if t.Username != "" {
		args = append(args, "-u", t.Username)
	}
	if t.Password != "" {
		args = append(args, "-p", t.Password)
	}
	if t.Threads > 0 {
		args = append(args, "-T", fmt.Sprintf("%d", t.Threads))
	}
	// RateLimit e Proxy não são diretamente suportados por enum4linux-ng via flags,
	// mas podem ser implementados via wrappers ou variáveis de ambiente se necessário.

	args = append(args, t.Flags...)

	logger.Info("Running Enum4linuxNG", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return fmt.Errorf("enum4linux-ng execution failed: %w", err)
	}
	return nil
}
