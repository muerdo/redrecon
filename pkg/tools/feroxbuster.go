package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunFeroxbuster(ctx context.Context, inputFile, outputFile, wordlist, tempDir, proxy string, headers []string, cookies string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Feroxbuster
	toolPath := config.GetToolPath("feroxbuster")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("feroxbuster disabled or not found")
	}

	profile, ok := utils.GetActiveWAFProfile(logger, "", tempDir)
	threads := t.Threads
	if threads == 0 && ok {
		threads = profile.Concurrency
	}
	// Use config proxy if argument is empty
	if proxy == "" {
		proxy = t.Proxy
	}

	if proxy == "" && ok {
		if len(profile.Proxies) > 0 {
			proxy = profile.Proxies[0] // Use the first proxy from the profile list
			logger.Debug("Using WAF profile proxy for Feroxbuster", "proxy", proxy)
		}
	}

	// Feroxbuster lê a lista de alvos do stdin quando a flag --stdin é usada.
	// Portanto, precisamos abrir o arquivo de entrada para passá-lo como stdin.
	input, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file for feroxbuster: %w", err)
	}
	defer input.Close()

	args := []string{
		"--stdin", // Lê URLs do stdin
		"-w", wordlist,
		"-o", outputFile,
		"-s", "200,301,403,405", // Filter status codes
	}

	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}
	if proxy != "" {
		args = append(args, "--proxy", proxy)
	}
	for _, h := range headers {
		args = append(args, "-H", h)
	}
	if cookies != "" {
		args = append(args, "--cookies", cookies)
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Feroxbuster", "args", strings.Join(args, " "))
	_, err = ExecuteCommandWithStdin(ctx, logger, input, toolPath, args...)
	return err
}
