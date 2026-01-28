package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

// RunHttpxVulnerabilityScan runs httpx with vulnerability-specific templates.
func RunHttpxVulnerabilityScan(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	toolPath := config.GetToolPath("httpx")
	if toolPath == "" {
		return fmt.Errorf("httpx binary not found")
	}

	httpxConfig := config.Cfg.Tools.Httpx
	templates := httpxConfig.VulnTemplates
	if len(templates) == 0 {
		// Fallback para um template padrão se não estiver configurado
		templates = []string{"http/vulnerabilities/"}
		logger.Warn("Httpx vulnerability templates not configured in config.yaml, using default.", "default", templates)
	}

	args := []string{"-l", inputFile, "-t", strings.Join(templates, ","), "-o", outputFile, "-json"}
	logger.Info("Running Httpx Vulnerability Scan", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}