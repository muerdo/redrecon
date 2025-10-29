package infra

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"

	"redrecon/pkg/recon" // Usado para SanitizeTargetForPath
)

// StartInfra inicia o fluxo de trabalho de varredura de infraestrutura.
func StartInfra(taskIdentifier, target string, skipSteps []string, logger *slog.Logger) (string, []string, error) {
	logger.Info("Starting infrastructure scan", "target", target)

	sanitizedTaskIdentifier := recon.SanitizeTargetForPath(taskIdentifier)
	resultsPath := filepath.Join("results", sanitizedTaskIdentifier, "infra")
	if err := os.MkdirAll(resultsPath, 0755); err != nil {
		return "", nil, fmt.Errorf("could not create infra results directory: %w", err)
	}

	nmapOutputFile := filepath.Join(resultsPath, "nmap_scan.txt")

	// Workflow de infraestrutura (atualmente apenas nmap)
	err := runNmap(context.Background(), target, nmapOutputFile, logger)
	if err != nil {
		return "", nil, fmt.Errorf("nmap scan failed: %w", err)
	}

	// Gerar sumário
	summary := fmt.Sprintf("✅ **Infra Scan Summary for: %s**\n\n", target)
	summary += "• **Nmap Scan:** Completed. Results saved to `nmap_scan.txt`.\n"
	summary += fmt.Sprintf("\n*Full results are saved in:* `%s`", resultsPath)

	files := []string{nmapOutputFile}

	return summary, files, nil
}

// runNmap executa o nmap no alvo.
func runNmap(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	logger.Info("Executing nmap scan. This may take a while...", "target", target)

	// -sV: Sonda portas abertas para determinar informações de serviço/versão
	// -T4: Define o tempo para agressivo (mais rápido)
	// -oN: Salva a saída no formato normal
	cmd := exec.CommandContext(ctx, "nmap", "-sV", "-T4", "-oN", outputFile, target)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nmap execution failed: %w\nStderr: %s", err, stderr.String())
	}

	logger.Info("Nmap scan completed", "output_file", outputFile)
	return nil
}