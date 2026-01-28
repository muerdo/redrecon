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

// RunBloodHound executa o coletor Python do BloodHound.
func RunBloodHound(ctx context.Context, domain string, creds types.Credentials, outputPrefix string, logger *slog.Logger) ([]string, error) {
	if !config.Cfg.Tools.BloodHound.Enabled {
		logger.Info("BloodHound is disabled in config, skipping.")
		return nil, nil
	}

	toolPath := config.GetToolPath("bloodhound.py")
	if _, err := exec.LookPath(toolPath); err != nil {
		return nil, fmt.Errorf("bloodhound.py not found in PATH and no custom path is set")
	}

	argsBuilder := utils.NewArgBuilder()
	argsBuilder.AddFlagIfNotEmpty("-d", domain).
		AddFlagIfNotEmpty("-u", creds.Username).
		AddFlagIfNotEmpty("-p", creds.Password).
		AddFlagIfNotEmpty("-hashes", creds.Hash).
		AddFlagIfNotEmpty("-c", config.Cfg.Tools.BloodHound.CollectionMethod).
		AddFlagIfNotEmpty("--zip", "").
		AddFlagIfNotEmpty("-f", outputPrefix) // O BloodHound adicionará a extensão .zip

	cmd := exec.CommandContext(ctx, toolPath, argsBuilder.Build()...)
	logger.Info("Running BloodHound collector", "command", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("BloodHound execution failed", "error", err, "output", string(output))
		return nil, fmt.Errorf("bloodhound.py failed: %w. Output: %s", err, string(output))
	}

	return []string{outputPrefix + ".zip"}, nil
}