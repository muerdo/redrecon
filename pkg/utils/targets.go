package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// GetTargets retorna uma lista de alvos a partir dos argumentos da CLI ou de um arquivo de entrada.
func GetTargets(args []string, inputFile string) ([]string, error) {
	if inputFile != "" {
		return readTargetsFromFile(inputFile)
	}
	if len(args) > 0 {
		// Retorna uma cópia para evitar modificações inesperadas no slice original de args
		targets := make([]string, len(args))
		copy(targets, args)
		return targets, nil
	}
	return nil, fmt.Errorf("nenhum alvo fornecido como argumento ou via arquivo de entrada")
}

// readTargetsFromFile lê um arquivo linha por linha e retorna uma lista de alvos.
func readTargetsFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("falha ao abrir o arquivo de alvos '%s': %w", filePath, err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			targets = append(targets, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("erro ao ler o arquivo de alvos '%s': %w", filePath, err)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("o arquivo de alvos '%s' está vazio ou não contém alvos válidos", filePath)
	}

	return targets, nil
}
