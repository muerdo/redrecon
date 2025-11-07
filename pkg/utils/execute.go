// pkg/utils/execute.go
package utils

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"fmt"
)
// ExecuteCommand executa um comando externo e retorna sua saída padrão.
// Ele registra a execução e os erros.
func ExecuteCommand(ctx context.Context, logger *slog.Logger, name string, arg ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, arg...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	output := stdout.String()

	if err != nil {
		// Log com mais detalhes quando um comando falha.
		logger.Error("Command execution failed", "command", name, "args", arg, "error", err, "stderr", stderr.String())
		// Retorna a saída padrão mesmo em caso de erro, pois pode conter informações úteis.
		return output, fmt.Errorf("command '%s' failed with stderr: %s: %w", name, stderr.String(), err)
	}

	// Log de depuração para execuções bem-sucedidas, incluindo stdout.
	logger.Debug("Command executed successfully", "command", name, "args", arg, "stdout", output)
	return output, nil
}
func ExecuteCommandWithInput(ctx context.Context, logger *slog.Logger, name string, arg []string, stdinInput string) (string, error) {
	cmd := exec.CommandContext(ctx, name, arg...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if stdinInput != "" {
		cmd.Stdin = bytes.NewBufferString(stdinInput)
	}

	err := cmd.Run()
	output := stdout.String()
	if err != nil {
		logger.Error("Command failed", "cmd", name, "args", arg, "stderr", stderr.String())
		return output, err
	}
	return output, nil
}

// CommandExists verifica se um comando existe no PATH do sistema.
func CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
