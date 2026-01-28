package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

// RunEnum4linuxNG executa o enum4linux-ng para enumeração SMB/Windows.
func RunEnum4linuxNG(ctx context.Context, target string, creds types.Credentials, outputFile string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Enum4linuxNG
	if !t.Enabled {
		logger.Info("enum4linux-ng is disabled in config, skipping.")
		return nil
	}
	toolPath := config.GetToolPath("enum4linux-ng")
	// Se não configurado, tenta PATH ou nome padrão
	if toolPath == "" {
		toolPath = "enum4linux-ng"
	}

	if !utils.CommandExists(toolPath) {
		return fmt.Errorf("enum4linux-ng disabled or not found")
	}

	// Criar diretório pai do output se não existir
	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for enum4linux-ng: %w", err)
	}

	args := []string{
		"-t", target,
		"-oJ", outputFile, // JSON output preferred
	}

	// Add credentials if available
	if creds.Username != "" && creds.Password != "" {
		args = append(args, "-u", creds.Username, "-p", creds.Password)
	}

	if t.Domain != "" {
		args = append(args, "-d", t.Domain)
	}
	if t.Threads > 0 {
		args = append(args, "-T", fmt.Sprintf("%d", t.Threads))
	}

	args = append(args, t.Flags...)

	logger.Info("Running Enum4linuxNG", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	if err != nil {
		return fmt.Errorf("enum4linux-ng execution failed: %w", err)
	}
	return nil
}
