package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunGospider(ctx context.Context, target, outputFile, tempDir, proxy string, headers []string, cookies string, logger *slog.Logger) error {
	// Check if tool is enabled (assuming we add it to config later, for now just check path)
	if !utils.CommandExists("gospider") {
		return fmt.Errorf("gospider not found")
	}

	args := []string{
		"-s", target,
		"-o", tempDir, // GoSpider creates a directory for output
		"--no-redirect",
		"-t", "5", // threads
		"-c", "5", // concurrent requests
		"-d", "3", // depth
	}

	if proxy != "" {
		args = append(args, "-p", proxy)
		utils.LogProxyUsage(logger, "gospider", proxy)
	}

	for _, h := range headers {
		args = append(args, "-H", h)
	}

	if cookies != "" {
		args = append(args, "--cookie", cookies)
	}

	// Add user agent
	ua := "Mozilla/5.0 (compatible; RedRecon/1.0)"
	if len(config.Cfg.Evasion.UserAgents) > 0 {
		ua = config.Cfg.Evasion.UserAgents[0]
	}
	args = append(args, "-u", ua)

	logger.Info("Running GoSpider", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, "gospider", args...)
	if err != nil {
		return err
	}

	// GoSpider outputs to a directory named after the domain. We need to find the output file and move/rename it or parse it.
	// Usually it creates `tempDir/domain_name/code-200.txt` etc.
	// For now, we assume the caller handles the output directory structure or we just leave it there.
	return nil
}
