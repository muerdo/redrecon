package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunHttpx(ctx context.Context, inputFile, outputFile, liveHostsOutputFile, tempDir string, followRedirects bool, ports string, techDetectOnly bool, proxy string, headers []string, cookies, username, password string, logger *slog.Logger) error {
	t := config.Cfg.Tools.Httpx
	toolPath := config.GetToolPath("httpx")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("httpx disabled or not found")
	}

	// Garante que o diretório de resposta exista dentro do diretório de resultados do recon do alvo.
	// O tempDir é 'results/alvo/recon/tmp', então o pai é 'results/alvo/recon'.
	responseDir := filepath.Join(filepath.Dir(tempDir), "output", "response")
	if err := os.MkdirAll(responseDir, 0755); err != nil {
		logger.Error("Failed to create httpx response directory", "path", responseDir, "error", err)
		return fmt.Errorf("failed to create httpx response directory: %w", err)
	}

	args := []string{
		"-l", inputFile,
		"-silent",
		"-random-agent",                    // Always use random user agent
		"-follow-redirects",                // Always follow redirects
		"-store-response",                  // Store responses
		"-store-response-dir", responseDir, // Directory to store responses
	}

	if proxy != "" {
		args = append(args, "-http-proxy", proxy)
	}

	for _, h := range headers {
		args = append(args, "-H", h)
	}

	if cookies != "" {
		args = append(args, "-cookie", cookies)
	}

	if username != "" && password != "" {
		// httpx supports basic auth via headers or specific flags?
		// Checking httpx help... it has -H.
		// It doesn't seem to have -u/-p for basic auth in the standard flags list I recall.
		// Let's use the Authorization header.
		authHeader := utils.BasicAuthHeader(username, password)
		args = append(args, "-H", authHeader)
	}

	if ports != "" {
		args = append(args, "-p", ports)
	}
	if techDetectOnly {
		args = append(args, "-tech-detect", "-json", "-title", "-status-code")
	}
	if outputFile != "" {
		args = append(args, "-o", outputFile)
	}
	if liveHostsOutputFile != "" {
		// Use -o for live hosts if no other output is specified, otherwise use a different flag if available
		// httpx requires -o when -oa is used. We can point -o to a dummy file.
		if outputFile == "" {
			dummyOutputFile := filepath.Join(tempDir, "httpx_dummy_output.txt")
			args = append(args, "-o", dummyOutputFile, "-oa", liveHostsOutputFile)
		}
	}

	logger.Info("Running httpx", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}
