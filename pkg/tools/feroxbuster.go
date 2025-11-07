package tools

import (
	"context"
	"os"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunFeroxbuster(ctx context.Context, inputFile, outputFile, wordlist, tempDir string, logger *slog.Logger) error {
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
	proxy := t.Proxy
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
	}

	if threads > 0 {
		args = append(args, "-t", fmt.Sprintf("%d", threads))
	}
	if proxy != "" {
		args = append(args, "--proxy", proxy)
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Feroxbuster", "args", strings.Join(args, " "))
	_, err = ExecuteCommandWithStdin(ctx, logger, input, toolPath, args...)
	return err
}