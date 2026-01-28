package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"

	"redrecon/internal/config"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

// RunBloodyAD executa um comando bloodyAD genérico.
func RunBloodyAD(ctx context.Context, domain, host string, creds types.Credentials, logger *slog.Logger, bloodyADArgs ...string) error {
	if !config.Cfg.Tools.BloodyAD.Enabled {
		logger.Info("BloodyAD is disabled in config, skipping.")
		return nil
	}

	toolPath := config.GetToolPath("bloodyAD")
	if !utils.CommandExists(toolPath) {
		return fmt.Errorf("bloodyAD not found in PATH and no custom path is set")
	}

	argsBuilder := utils.NewArgBuilder()
	argsBuilder.AddFlagIfNotEmpty("-d", domain).
		AddFlagIfNotEmpty("-u", creds.Username).
		AddFlagIfNotEmpty("-p", creds.Password).
		AddFlagIfNotEmpty("--host", host)

	// Adiciona -k se a autenticação for Kerberos (sem senha/hash)
	if creds.Password == "" && creds.Hash == "" {
		argsBuilder.AddFlagIf(true, "-k", "")
	}

	argsBuilder.AddSlice(bloodyADArgs)
	argsBuilder.AddSlice(config.Cfg.Tools.BloodyAD.ExtraArgs)

	cmd := exec.CommandContext(ctx, toolPath, argsBuilder.Build()...)
	logger.Info("Running BloodyAD", "command", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("BloodyAD execution failed", "error", err, "output", string(output))
		return fmt.Errorf("bloodyAD failed: %w. Output: %s", err, string(output))
	}

	logger.Info("BloodyAD command executed successfully", "output", string(output))
	return nil
}