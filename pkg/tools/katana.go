package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunKatana(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger, extraArgs ...string) error {
	t := config.Cfg.Recon.Katana
	toolPath := config.GetToolPath("katana")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("katana disabled or not found")
	}

	profile, ok := utils.GetActiveWAFProfile(logger, "", tempDir)
	depth := t.Depth
	proxy := t.Proxy
	if proxy == "" && ok && len(profile.Proxies) > 0 {
		proxy = profile.Proxies[0] // Usa o primeiro proxy da lista do perfil
		logger.Debug("Using WAF profile proxy for Katana", "proxy", proxy)
	}

	args := []string{
		"-list", inputFile,
		"-o", outputFile,
		"-silent",
	}
	if depth > 0 {
		args = append(args, "-d", fmt.Sprintf("%d", depth))
	}
	// Obtém o proxy configurado e o usa se não houver um proxy específico do WAF
	if configuredProxy := utils.GetGlobalProxy(); configuredProxy != "" {
		proxy = configuredProxy
	} else if ok && len(profile.Proxies) > 0 {
		proxy = profile.Proxies[0]
	}
	if config.Cfg.Evasion.Enabled {
		args = append(args, "-d", fmt.Sprintf("%d", depth))
	}
	if proxy != "" {
		args = append(args, "-proxy", proxy)
	}
	args = append(args, t.ExtraArgs...)
	args = append(args, extraArgs...)

	logger.Info("Running Katana", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}
