package search

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"log/slog"
	"redrecon/pkg/utils"

	"github.com/fatih/color"
)

func init() {
	// Desativa a cor se não estiver em um terminal (útil para o bot do Discord)
	color.NoColor = !isTerminal()
}

// ExecuteSearch percorre os diretórios de resultados e procura por um termo.
func ExecuteSearch(searchTerm, targetScope string, listOnly, useRegex bool) (string, error) {
	var results strings.Builder
	var searchPattern *regexp.Regexp
	var err error

	// Define o caminho base da busca.
	basePath := "results"
	if targetScope != "" {
		// Se um escopo de alvo é fornecido, o caminho da busca é restrito a esse alvo.
		basePath = filepath.Join(basePath, utils.SanitizeTargetForPath(targetScope))
		slog.Debug("Search basePath restricted", "basePath", basePath, "targetScope", targetScope)
	}

	// Garante que o diretório de busca exista.
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		if targetScope != "" {
			slog.Warn("Search directory for target does not exist, no search performed.", "path", basePath)
			return fmt.Sprintf("Nenhum resultado encontrado para o alvo '%s' (diretório não existe).", targetScope), nil
		}
		// Se nenhum alvo foi especificado e o diretório 'results' não existe.
		slog.Warn("Base 'results' directory does not exist, no search performed.", "path", basePath)
		return "Diretório 'results' não encontrado. Execute uma varredura primeiro.", nil
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

	walkErr := filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Pula diretórios
		if info.IsDir() {
			return nil
		}

		// Pula arquivos muito grandes ou que não são de texto para evitar consumo excessivo de memória.
		if info.Size() > 50*1024*1024 || !isTextFile(path) { // Limite de 50MB
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			slog.Warn("Could not open file during search", "path", path, "error", err)
			return nil
		}
		defer file.Close()

		// **LÓGICA DE LEITURA APRIMORADA**: Lê o arquivo em blocos para evitar erros de "token too long".
		content, err := io.ReadAll(file)
		if err != nil {
			slog.Warn("Could not read file content during search", "path", path, "error", err)
			return nil // Pula este arquivo, mas continua a busca
		}

		// Se não houver correspondência no conteúdo, não há mais nada a fazer para este arquivo.
		if !searchPattern.MatchString(string(content)) {
			return nil
		}

		// Se encontrarmos uma correspondência, processamos o arquivo.
		if listOnly {
			results.WriteString(fmt.Sprintf("%s\n", path))
			return nil // Para de processar este arquivo, pois já foi listado.
		}

		results.WriteString(fmt.Sprintf("\n%s\n", color.YellowString(path)))

		// Para exibir o contexto, dividimos o conteúdo em linhas APÓS encontrar uma correspondência.
		lines := strings.Split(string(content), "\n")
		for i, line := range lines {
			if searchPattern.MatchString(line) {
				// Garante que a linha não seja excessivamente longa antes de imprimir.
				if len(line) > 4096 {
					line = line[:4096] + "... (linha truncada)"
				}

				highlightedLine := searchPattern.ReplaceAllStringFunc(line, func(match string) string {
					return highlight(match)
				})
				results.WriteString(fmt.Sprintf("  %d: %s\n", i+1, highlightedLine))
			}
		}

		return nil
	})

	if walkErr != nil {
		// Este erro só deve acontecer se houver um problema com o próprio `filepath.Walk`,
		// como um erro de permissão no diretório base, não um erro de leitura de arquivo.
		slog.Error("A critical error occurred during the directory walk", "error", walkErr)
		return "", fmt.Errorf("a busca falhou criticamente: %w", walkErr)
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

// isTerminal verifica se a saída padrão é um terminal.
func isTerminal() bool {
	stat, _ := os.Stdout.Stat()
	// Verifica se o modo do arquivo tem o bit de dispositivo de caractere (CharDevice) definido.
	// Isso geralmente é verdadeiro para terminais.
	return (stat.Mode() & os.ModeCharDevice) != 0
}