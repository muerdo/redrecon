package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/pkg/utils"
)

func RunSemgrep(ctx context.Context, targetDir, outputFile string, logger *slog.Logger) error {
	if !utils.CommandExists("semgrep") {
		return fmt.Errorf("semgrep not found")
	}

	args := []string{
		"scan",
		"--config", "auto", // Use auto config or specific ruleset
		"--json",
		"-o", outputFile,
		targetDir,
	}

	logger.Info("Running Semgrep", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, "semgrep", args...)
	return err
}
