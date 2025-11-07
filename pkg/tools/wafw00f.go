package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunWafw00f(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Recon.Wafw00f
	toolPath := config.GetToolPath("wafw00f")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("wafw00f disabled or not found")
	}

	profile, ok := utils.GetActiveWAFProfile(logger, "", tempDir)
	proxy := t.Proxy
	if proxy == "" && ok && len(profile.Proxies) > 0 {
		proxy = profile.Proxies[0] // Usa o primeiro proxy da lista do perfil
		logger.Debug("Using WAF profile proxy for Wafw00f", "proxy", proxy)
	}

	args := []string{
		"-i", inputFile,
		"-o", outputFile,
		"-f", "json",
	}
	if proxy != "" {
		args = append(args, "-p", proxy)
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Wafw00f", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}
