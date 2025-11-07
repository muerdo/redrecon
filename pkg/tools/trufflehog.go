package tools

import (
	"context"
	"fmt"
	"os"
	"bytes"
	"os/exec"
	"log/slog"
	"strings"

	"redrecon/internal/config"
)

// RunTruffleHog executes the trufflehog scanner on a given path.
func RunTruffleHog(ctx context.Context, path, outputFile string, rateLimit, concurrency int, proxy string, logger *slog.Logger) error {
	t := config.Cfg.Tools.TruffleHog
	toolPath := config.GetToolPath("trufflehog")
	if toolPath == "" || !t.Enabled {
		logger.Info("TruffleHog is disabled or not found, skipping.")
		return nil
	}

	args := []string{
		"filesystem",
		path,
		"--json",
		"--no-update", // Adicionado para prevenir erros de atualização automática por permissão
	}

	if t.NoVerify {
		args = append(args, "--no-verify")
	}
	if rateLimit > 0 {
		args = append(args, "--rate-limit", fmt.Sprintf("%d", rateLimit))
	}
	if concurrency > 0 {
		args = append(args, "--concurrency", fmt.Sprintf("%d", concurrency))
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running TruffleHog", "args", strings.Join(args, " "))
	
	cmd := exec.CommandContext(ctx, toolPath, args...)
	
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	err := cmd.Run()
	if err != nil {
		logger.Error("Command execution failed", "command", toolPath, "args", strings.Join(args, " "), "error", err, "stderr", stderrBuf.String())
		return fmt.Errorf("command '%s' failed with stderr: %s: %w", toolPath, stderrBuf.String(), err)
	}

	// Escreve a saída JSON capturada para o arquivo de saída
	if err := os.WriteFile(outputFile, stdoutBuf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write trufflehog output to file %s: %w", outputFile, err)
	}

	logger.Info("TruffleHog scan completed successfully.", "output_file", outputFile)
	return nil
}