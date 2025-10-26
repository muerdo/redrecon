package search

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/fatih/color"
)

// ExecuteSearch percorre os diretórios de resultados e procura por um termo.
func ExecuteSearch(searchTerm, targetScope string, listOnly, useRegex bool) (string, error) {
	var results strings.Builder
	var searchPattern *regexp.Regexp
	var err error

	resultsPath := "results"
	if targetScope != "" {
		resultsPath = filepath.Join(resultsPath, targetScope)
	}

	if useRegex {
		searchPattern, err = regexp.Compile(searchTerm)
		if err != nil {
			return "", fmt.Errorf("invalid regular expression: %w", err)
		}
	} else {
		// Para busca de texto simples, crie um regex case-insensitive
		searchPattern, err = regexp.Compile("(?i)" + regexp.QuoteMeta(searchTerm))
		if err != nil {
			return "", fmt.Errorf("could not compile search term: %w", err)
		}
	}

	highlight := color.New(color.FgRed, color.Bold).SprintFunc()

	walkErr := filepath.Walk(resultsPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !isTextFile(path) {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			return nil // Ignora arquivos que não podem ser abertos
		}
		defer file.Close()

		// **A CORREÇÃO ESTÁ AQUI**
		// Aumenta o buffer do scanner para lidar com linhas muito longas.
		const maxCapacity = 1 * 1024 * 1024 // 1 MB
		buf := make([]byte, maxCapacity)
		scanner := bufio.NewScanner(file)
		scanner.Buffer(buf, maxCapacity)

		var fileHasMatch bool
		var fileMatches strings.Builder
		lineNumber := 0

		for scanner.Scan() {
			lineNumber++
			line := scanner.Text()

			if searchPattern.MatchString(line) {
				if !fileHasMatch {
					fileHasMatch = true
					if listOnly {
						results.WriteString(fmt.Sprintf("%s\n", path))
						return nil // Para de processar este arquivo, pois já foi listado
					}
					fileMatches.WriteString(fmt.Sprintf("\n%s\n", color.YellowString(path)))
				}

				if !listOnly {
					highlightedLine := searchPattern.ReplaceAllStringFunc(line, func(match string) string {
						return highlight(match)
					})
					fileMatches.WriteString(fmt.Sprintf("  %d: %s\n", lineNumber, highlightedLine))
				}
			}
		}

		if err := scanner.Err(); err != nil {
			// Retorna um erro mais descritivo
			return fmt.Errorf("error scanning file %s: %w", path, err)
		}

		if fileHasMatch && !listOnly {
			results.WriteString(fileMatches.String())
		}

		return nil
	})

	if walkErr != nil {
		return "", fmt.Errorf("error during search: %w", walkErr)
	}

	if results.Len() == 0 {
		return "No matches found.", nil
	}

	return results.String(), nil
}

// isTextFile faz uma verificação simples para evitar a leitura de arquivos binários.
func isTextFile(path string) bool {
	// Extensões comuns de texto nos resultados
	textExtensions := []string{".txt", ".json", ".html", ".js", ".xml", ".log", ".csv", ".md"}
	ext := strings.ToLower(filepath.Ext(path))
	for _, tExt := range textExtensions {
		if ext == tExt {
			return true
		}
	}
	// Se a extensão não for conhecida, assume que é texto, a menos que seja um executável ou imagem.
	binaryExtensions := []string{".exe", ".bin", ".dll", ".so", ".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz"}
	for _, bExt := range binaryExtensions {
		if ext == bExt {
			return false
		}
	}
	return true
}