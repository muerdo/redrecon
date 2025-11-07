package tools

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"syscall"
)

// ExecuteCommand executa um comando e retorna sua saída padrão (stdout).
// Erros, incluindo stderr não vazio, são retornados como um erro.
func ExecuteCommand(ctx context.Context, logger *slog.Logger, command string, args ...string) (string, error) {
	return ExecuteCommandWithStdin(ctx, logger, nil, command, args...)
}

// ExecuteCommandWithStdin executa um comando, passando dados para seu stdin, e retorna sua saída padrão (stdout).
func ExecuteCommandWithStdin(ctx context.Context, logger *slog.Logger, stdin io.Reader, command string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if stdin != nil {
		cmd.Stdin = stdin
	}

	// Garante que o processo filho seja terminado se o processo pai morrer
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	logger.Debug("Executing command", "command", command, "args", strings.Join(args, " "))

	err := cmd.Run()

	// Log de stderr mesmo em caso de sucesso, para depuração
	if stderr.Len() > 0 {
		logger.Debug("Command stderr", "command", command, "stderr", stderr.String())
	}

	if err != nil {
		// Verifica se o erro foi um cancelamento de contexto
		if ctx.Err() == context.Canceled {
			logger.Warn("Command execution canceled by context", "command", command)
			return "", fmt.Errorf("command '%s' canceled: %w", command, ctx.Err())
		}

		// Constrói uma mensagem de erro mais detalhada
		errorMsg := fmt.Sprintf("command '%s' failed with stderr: %s: %v", command, strings.TrimSpace(stderr.String()), err)
		logger.Error("Command execution failed", "command", command, "args", strings.Join(args, " "), "error", err, "stderr", stderr.String())
		return stdout.String(), fmt.Errorf(errorMsg)
	}

	return stdout.String(), nil
}