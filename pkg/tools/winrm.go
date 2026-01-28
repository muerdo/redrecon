package tools

import (
	"context"
	"fmt"
	"log/slog"

	"redrecon/internal/config"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

// RunEvilWinRM establishes a WinRM shell.
// Note: Evil-WinRM is interactive. Getting it to work non-interactively for "recon" might mean running commands.
// For interactive mode, we might just spawn the process attached to stdin/stdout.
func RunEvilWinRM(ctx context.Context, target string, creds types.Credentials, logger *slog.Logger) error {
	toolPath := config.GetToolPath("evil-winrm")
	if toolPath == "" {
		return fmt.Errorf("evil-winrm not configured")
	}

	argsBuilder := utils.NewArgBuilder()
	argsBuilder.AddFlagIfNotEmpty("-i", target)
	argsBuilder.AddFlagIfNotEmpty("-u", creds.Username)
	argsBuilder.AddFlagIfNotEmpty("-p", creds.Password)
	if creds.Hash != "" {
		argsBuilder.AddFlagIfNotEmpty("-H", creds.Hash)
	}

	// If we want to execute a command and return:
	// argsBuilder.AddFlagIfNotEmpty("-x", "whoami")

	// For interactive shell access (as requested in "Interactive AD Explorer"):
	// We need to pass Stdin/Stdout/Stderr directly.
	logger.Info("Starting Interactive Evil-WinRM session...", "target", target)

	return utils.ExecuteInteractiveCommand(ctx, toolPath, argsBuilder.Build()...)
}
