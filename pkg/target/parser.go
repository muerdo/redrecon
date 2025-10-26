package target

import (
	"bufio"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// IsTargetFile verifica se o argumento fornecido é um caminho para um arquivo .txt.
func IsTargetFile(targetArg string) bool {
	return strings.HasSuffix(strings.ToLower(targetArg), ".txt")
}

// ParseTargetFile lê um arquivo de texto, normaliza cada linha para extrair um domínio raiz
// e retorna uma lista de alvos únicos.
// - "sub.example.com" -> "example.com"
// - "*.example.com" -> "example.com"
// - "https://www.example.com/path" -> "example.com"
func ParseTargetFile(filePath string) ([]string, error) {
	slog.Info("Parsing target file", "path", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open target file %s: %w", filePath, err)
	}
	defer file.Close()

	uniqueTargets := make(map[string]struct{})
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue // Ignora linhas vazias e comentários
		}

		normalized, err := normalizeTarget(line)
		if err != nil {
			slog.Warn("Could not normalize target, skipping", "input", line, "error", err)
			continue
		}

		if normalized != "" {
			uniqueTargets[normalized] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading target file %s: %w", filePath, err)
	}

	var targets []string
	for t := range uniqueTargets {
		targets = append(targets, t)
	}

	slog.Info("Found unique targets in file", "count", len(targets))
	return targets, nil
}

// normalizeTarget extrai o domínio efetivo de uma string de entrada.
func normalizeTarget(input string) (string, error) {
	// Remove wildcard prefix
	input = strings.TrimPrefix(input, "*.")

	// Se não tiver um esquema, adiciona um para que a biblioteca url possa fazer o parse corretamente.
	if !strings.HasPrefix(input, "http://") && !strings.HasPrefix(input, "https://") {
		input = "http://" + input
	}

	parsedURL, err := url.Parse(input)
	if err != nil {
		return "", fmt.Errorf("could not parse URL: %w", err)
	}

	// Usa publicsuffix para extrair o domínio raiz (e.g., 'example.com' de 'sub.example.com')
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(parsedURL.Hostname())
	return eTLDPlusOne, err
}

