package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"redrecon/internal/config"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

// RunLdapDump executes ldapdomaindump.
func RunLdapDump(ctx context.Context, target string, domain string, creds types.Credentials, outputDir string, logger *slog.Logger) error {
	// Check if tool is enabled
	if !config.Cfg.Tools.Ldapdomaindump.Enabled {
		logger.Info("ldapdomaindump is disabled in config, skipping.")
		return nil
	}

	toolPath := config.GetToolPath("ldapdomaindump")
	// ldapdomaindump usually runs via python module or script `ldapdomaindump`
	// Fallback to "ldapdomaindump" in PATH if not set
	if toolPath == "" {
		toolPath = "ldapdomaindump"
	}

	if !utils.CommandExists(toolPath) {
		return fmt.Errorf("ldapdomaindump not found in PATH")
	}

	// Create output dir
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output dir for ldapdump: %w", err)
	}

	// ldapdomaindump -u 'user' -p 'pass' -d 'domain' -o 'outdir' target
	argsBuilder := utils.NewArgBuilder()

	if creds.Username != "" {
		argsBuilder.AddFlagIfNotEmpty("-u", creds.Username)
	}
	if creds.Password != "" {
		argsBuilder.AddFlagIfNotEmpty("-p", creds.Password)
	}
	if domain != "" {
		argsBuilder.AddFlagIfNotEmpty("-d", domain)
	} else if creds.Domain != "" {
		argsBuilder.AddFlagIfNotEmpty("-d", creds.Domain)
	}

	argsBuilder.AddFlagIfNotEmpty("-o", outputDir)
	argsBuilder.AddFlagIfNotEmpty("", target)

	cmd := exec.CommandContext(ctx, toolPath, argsBuilder.Build()...)
	logger.Info("Running ldapdomaindump", "command", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("ldapdomaindump failed", "error", err, "output", string(output))
		// Log output to file
		utils.WriteLines(filepath.Join(outputDir, "ldapdump_error.log"), []string{string(output)})
		return fmt.Errorf("ldapdomaindump failed: %w", err)
	}

	return nil
}
