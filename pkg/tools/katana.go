package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunKatana(ctx context.Context, inputFile, outputFile, tempDir, proxy string, headers []string, cookies string, logger *slog.Logger, extraArgs ...string) error {
	t := config.Cfg.Tools.Katana
	toolPath := config.GetToolPath("katana")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("katana disabled or not found")
	}

	profile, ok := utils.GetActiveWAFProfile(logger, "", tempDir)
	depth := t.Depth

	// Prioritize passed proxy, then WAF profile, then config
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
	// Obtém o proxy configurado e o usa se não houver um proxy específico do WAF ou passado
	if proxy == "" {
		if configuredProxy := utils.GetGlobalProxy(); configuredProxy != "" {
			proxy = configuredProxy
		} else if t.Proxy != "" {
			proxy = t.Proxy
		}
	}
	if config.Cfg.Evasion.Enabled {
		// Add evasion flags if needed, e.g. random user agent is handled by katana default or extra args
		// For now, removing the redundant depth flag
	}
	if proxy != "" {
		args = append(args, "-proxy", proxy)
	}
	for _, h := range headers {
		args = append(args, "-H", h)
	}
	if cookies != "" {
		args = append(args, "-H", fmt.Sprintf("Cookie: %s", cookies))
	}
	args = append(args, t.ExtraArgs...)
	args = append(args, extraArgs...)

	logger.Info("Running Katana", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}
