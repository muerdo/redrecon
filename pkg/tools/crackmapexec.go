package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"redrecon/internal/config"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

// RunCrackMapExec executa o CrackMapExec contra uma lista de alvos.
func RunCrackMapExec(ctx context.Context, targets []string, protocol string, creds types.Credentials, logFile string, logger *slog.Logger) error {
	if !config.Cfg.Tools.CrackMapExec.Enabled {
		logger.Info("CrackMapExec is disabled in config, skipping.")
		return nil
	}

	toolPath := config.GetToolPath("crackmapexec")
	if !utils.CommandExists(toolPath) {
		return fmt.Errorf("crackmapexec not found in PATH and no custom path is set")
	}

	// FIX: CrackMapExec fails if /tmp/cme_hosted already exists (bug in first_run.py)
	// We proactively remove it to ensure a clean run.
	if err := os.RemoveAll("/tmp/cme_hosted"); err != nil {
		logger.Warn("Failed to clean up /tmp/cme_hosted", "error", err)
	}

	argsBuilder := utils.NewArgBuilder()
	argsBuilder.AddFlagIfNotEmpty("", protocol)
	argsBuilder.AddSlice(targets)

	// Adiciona credenciais
	if creds.Username != "" {
		argsBuilder.AddFlagIfNotEmpty("-u", creds.Username)
	}

	if creds.Domain != "" {
		argsBuilder.AddFlagIfNotEmpty("-d", creds.Domain)
	}

	if creds.Password != "" {
		argsBuilder.AddFlagIfNotEmpty("-p", creds.Password)
	} else if creds.Hash != "" {
		argsBuilder.AddFlagIfNotEmpty("-H", creds.Hash)
	}

	// Adiciona logging e argumentos extras
	argsBuilder.AddFlagIfNotEmpty("--log", logFile)
	argsBuilder.AddSlice(config.Cfg.Tools.CrackMapExec.ExtraArgs)

	cmd := exec.CommandContext(ctx, toolPath, argsBuilder.Build()...)
	logger.Info("Running CrackMapExec", "command", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("CrackMapExec execution failed", "error", err, "output", string(output))
		return fmt.Errorf("crackmapexec failed: %w. Output: %s", err, string(output))
	}

	logger.Info("CrackMapExec scan completed successfully.", "logfile", logFile)
	return nil
}
