package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

// RunLDAPDomainDump executes ldapdomaindump against the target.
func RunLDAPDomainDump(ctx context.Context, domain string, target string, creds types.Credentials, outputDir string, logger *slog.Logger) error {
	toolPath, err := exec.LookPath("ldapdomaindump")
	if err != nil {
		return fmt.Errorf("ldapdomaindump not found in PATH")
	}

	argsBuilder := utils.NewArgBuilder()

	if creds.Username != "" {
		argsBuilder.AddFlagIfNotEmpty("-u", creds.Username)
	}
	if creds.Password != "" {
		argsBuilder.AddFlagIfNotEmpty("-p", creds.Password)
	}
	if domain != "" {
		argsBuilder.AddFlagIfNotEmpty("-d", domain)
	}

	argsBuilder.AddFlagIfNotEmpty("-o", outputDir)

	// Add the protocol prefix if missing
	targetUrl := target
	if !strings.HasPrefix(target, "ldap://") && !strings.HasPrefix(target, "ldaps://") {
		targetUrl = "ldap://" + target
	}
	argsBuilder.AddFlagIfNotEmpty("", targetUrl)

	cmd := exec.CommandContext(ctx, toolPath, argsBuilder.Build()...)
	logger.Info("Running LDAPDomainDump", "command", cmd.String())

	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("LDAPDomainDump execution failed", "error", err, "output", string(output))
		return fmt.Errorf("ldapdomaindump failed: %w", err)
	}

	logger.Info("LDAPDomainDump completed", "output_dir", outputDir)
	return nil
}
