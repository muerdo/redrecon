package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunDirsearch(ctx context.Context, inputFile, outputFile, wordlist, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Dirsearch
	toolPath := config.GetToolPath("dirsearch")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("dirsearch disabled or not found")
	}

	profile, ok := utils.GetActiveWAFProfile(logger, "", tempDir)
	threads := t.Threads
	if threads == 0 && ok {
		threads = profile.Concurrency
	}
	proxy := t.Proxy
	if proxy == "" && ok {
		if len(profile.Proxies) > 0 {
			proxy = profile.Proxies[0] // Use the first proxy from the profile list
			logger.Debug("Using WAF profile proxy for Dirsearch", "proxy", proxy)
		}
	}

	args := []string{
		"-l", inputFile,
		"-w", wordlist,
		"-o", outputFile,
	}
	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}
	if proxy != "" {
		args = append(args, "--proxy", proxy)
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Dirsearch", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}