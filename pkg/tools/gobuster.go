package tools

import (
	"context"
	"os"
	"fmt"
	"log/slog"
	"sync"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunGobuster(ctx context.Context, inputFile, outputFile, wordlist, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Gobuster
	toolPath := config.GetToolPath("gobuster")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("gobuster disabled or not found")
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
			logger.Debug("Using WAF profile proxy for Gobuster", "proxy", proxy)
		}
	}

	// Gobuster no modo 'dir' não aceita uma lista de URLs diretamente.
	// Precisamos iterar sobre cada URL no arquivo de entrada.
	targets, err := utils.ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read targets for gobuster: %w", err)
	}

	if len(targets) == 0 {
		logger.Warn("Gobuster input file is empty, skipping.", "file", inputFile)
		return nil
	}

	// Cria um arquivo de saída temporário para agregar os resultados.
	// O Gobuster anexa ao arquivo de saída, então podemos usar o mesmo para todas as execuções.
	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open output file for gobuster: %w", err)
	}
	f.Close() // Fecha imediatamente, o gobuster irá reabri-lo.

	var wg sync.WaitGroup
	// Usa um semáforo para limitar a concorrência, baseado no número de threads configurado para o gobuster.
	concurrencyLimit := make(chan struct{}, threads)

	for _, targetURL := range targets {
		wg.Add(1)
		concurrencyLimit <- struct{}{}

		go func(u string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			// Monta os argumentos para cada alvo individual
			args := []string{
				"dir",
				"-u", u,
				"-w", wordlist,
				"-o", outputFile, // Anexa ao mesmo arquivo de saída
				"-a", // Anexa ao arquivo de saída
			}
			if threads > 0 {
				args = append(args, "-t", fmt.Sprintf("%d", threads))
			}
			if proxy != "" {
				args = append(args, "-p", proxy)
			}
			args = append(args, t.ExtraArgs...)

			logger.Info("Running Gobuster for target", "target", u)
			_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
			if err != nil {
				logger.Warn("Gobuster failed for a single target, but continuing", "target", u, "error", err)
			}
		}(targetURL)
	}

	wg.Wait()
	logger.Info("Gobuster scan for all targets completed.", "output_file", outputFile)
	return nil
}