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

// RunCertipy executa o Certipy para encontrar vulnerabilidades no AD CS.
func RunCertipy(ctx context.Context, domain string, targets []string, creds types.Credentials, outputFile string, logger *slog.Logger) error {
	if !config.Cfg.Tools.Certipy.Enabled {
		logger.Info("Certipy is disabled in config, skipping.")
		return nil
	}

	toolPath := config.GetToolPath("certipy")
	if _, err := exec.LookPath(toolPath); err != nil {
		return fmt.Errorf("certipy not found in PATH and no custom path is set")
	}

	dcIp := ""
	if len(targets) > 0 {
		dcIp = targets[0]
	}

	argsBuilder := utils.NewArgBuilder()
	argsBuilder.AddFlagIfNotEmpty("", "find"). // Ação principal do Certipy
		AddFlagIfNotEmpty("-u", creds.Username+"@"+domain).
		AddFlagIfNotEmpty("-p", creds.Password).
		AddFlagIfNotEmpty("-hashes", creds.Hash).
		AddFlagIfNotEmpty("-dc-ip", dcIp).
		AddFlagIfNotEmpty("-json", outputFile)
	argsBuilder.AddSlice(config.Cfg.Tools.Certipy.ExtraArgs)

	cmd := exec.CommandContext(ctx, toolPath, argsBuilder.Build()...)
	logger.Info("Running Certipy", "command", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("Certipy execution failed", "error", err, "output", string(output))
		return fmt.Errorf("certipy failed: %w. Output: %s", err, string(output))
	}

	return nil
}