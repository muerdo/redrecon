package utils

import (
	"bufio"
	"fmt"
	"net/url"
	"regexp"
	"log/slog"
	"sync"
	"os"
	"strings"
)

var fileMutexes = make(map[string]*sync.Mutex)
var mapMutex = &sync.Mutex{}

// CombineAndDeduplicateFiles lê o conteúdo de vários arquivos de origem, combina,
// remove duplicatas e escreve o resultado em um arquivo de destino.
// Esta função agora aceita tanto caminhos de arquivo quanto strings de conteúdo bruto como fontes.
func CombineAndDeduplicateFiles(destFile string, sources ...string) error {
	// Usa um mapa para garantir a deduplicação automática.
	allItems := make(map[string]struct{})

	// 1. Lê os itens existentes no arquivo de destino, se ele já existir.
	if FileExistsAndIsNotEmpty(destFile) {
		existingItems, err := ReadLines(destFile)
		if err != nil {
			return fmt.Errorf("error reading existing destination file: %w", err)
		}
		for _, item := range existingItems {
			allItems[item] = struct{}{}
		}
	}

	// 2. Processa todas as fontes (sejam arquivos ou conteúdo de string).
	for _, src := range sources {
		if src == "" {
			continue // Pula fontes vazias.
		}

		// Verifica se a fonte é um arquivo existente.
		if FileExistsAndIsNotEmpty(src) {
			// É um caminho de arquivo.
			lines, err := ReadLines(src)
			if err != nil {
				// Loga um aviso em vez de retornar um erro fatal se um arquivo de origem não puder ser aberto.
				slog.Warn("Could not read source file during combination, skipping.", "file", src, "error", err)
				continue
			}
			for _, line := range lines {
				allItems[line] = struct{}{}
			}
		} else {
			// Não é um arquivo, trata como conteúdo de string.
			// Divide a string em linhas.
			scanner := bufio.NewScanner(strings.NewReader(src))
			for scanner.Scan() {
				cleanItem := strings.TrimSpace(scanner.Text())
				if cleanItem != "" {
					allItems[cleanItem] = struct{}{}
				}
			}
		}
	}

	// 3. Escreve a lista combinada e deduplicada de volta no arquivo de destino.
	// Garante que a escrita no mesmo arquivo de destino seja serializada.
	mapMutex.Lock()
	mu, ok := fileMutexes[destFile]
	if !ok {
		mu = &sync.Mutex{}
		fileMutexes[destFile] = mu
	}
	mapMutex.Unlock()

	mu.Lock()
	defer mu.Unlock()

	err := WriteLines(destFile, allItems)

	return err
}

// CountLines é uma função auxiliar para contar linhas em um arquivo.
func CountLines(path string) int {
	if !FileExistsAndIsNotEmpty(path) {
		return 0
	}
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count++
	}
	return count
}

// WriteLines escreve um conjunto de strings (de um mapa) para um arquivo, uma por linha.
func WriteLines(filePath string, lines map[string]struct{}) error {
	output, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to open file for writing: %w", err)
	}
	defer output.Close()

	writer := bufio.NewWriter(output)
	for line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("failed to write line to file: %w", err)
		}
	}

	return writer.Flush()
}

// PreprocessURLsForHttpx lê um arquivo de entrada, garante que cada linha seja uma URL válida
// com um esquema (http/https), e retorna o caminho para um novo arquivo temporário com as URLs limpas.
func PreprocessURLsForHttpx(inputFile, tempDir string, logger *slog.Logger) (string, error) {
	lines, err := ReadLines(inputFile)
	if err != nil {
		return "", fmt.Errorf("failed to read input file for preprocessing: %w", err)
	}

	validURLs := make(map[string]struct{})
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}

		// Se a linha já tem um esquema, considera-a válida.
		if strings.HasPrefix(trimmedLine, "http://") || strings.HasPrefix(trimmedLine, "https://") {
			validURLs[trimmedLine] = struct{}{}
			continue
		}

		// Se não tiver esquema, tenta adicionar 'http://' e 'https://'.
		// Isso lida com entradas como 'example.com' ou 'example.com:8080'.
		validURLs["http://"+trimmedLine] = struct{}{}
		validURLs["https://"+trimmedLine] = struct{}{}
	}

	if len(validURLs) == 0 {
		return inputFile, nil // Retorna o arquivo original se nenhuma URL válida for encontrada, para evitar erros.
	}

	// Cria um novo arquivo temporário com as URLs processadas.
	tempFile, err := os.CreateTemp(tempDir, "httpx_processed_*.txt")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file for processed URLs: %w", err)
	}
	defer tempFile.Close()

	return tempFile.Name(), WriteLines(tempFile.Name(), validURLs)
}

// FilterScanTargets lê um arquivo de alvos e remove URLs que apontam para arquivos estáticos.
func FilterScanTargets(inputFile, outputFile string, logger *slog.Logger) error {
	// Lista de extensões de arquivos estáticos a serem ignoradas.
	disallowedExtensions := []string{
		// Imagens
		".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico",
		// Fontes
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		// Estilos
		".css",
		// Documentos e Mídia
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".mp3", ".mp4", ".avi", ".mov",
		".zip", ".rar", ".tar", ".gz",
	}

	// Lista de subdomínios comuns de CDN/imagens a serem ignorados.
	disallowedHostSubstrings := []string{
		"images.", "img.", "cdn.", "assets.", "static.",
	}

	// Regex para limpar lixo no final da URL.
	urlCleanerRegex := regexp.MustCompile(`^https?:\/\/[^\s"']*[^\s"'.:,]`)

	lines, err := ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file for filtering: %w", err)
	}

	filteredURLs := make(map[string]struct{})
	for _, line := range lines {
		// 1. Limpa a URL de lixo e caracteres inválidos.
		cleanedLine := urlCleanerRegex.FindString(line)
		if cleanedLine == "" {
			continue
		}

		// 2. Tenta fazer o parse da URL para validar a estrutura e extrair o host.
		parsedURL, err := url.Parse(cleanedLine)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			continue // Descarta se não for uma URL válida.
		}

		lowerPath := strings.ToLower(parsedURL.Path)
		lowerHost := strings.ToLower(parsedURL.Host)
		isDisallowed := false

		// 3. Filtra por extensão de arquivo estático.
		for _, ext := range disallowedExtensions {
			if strings.HasSuffix(lowerPath, ext) {
				isDisallowed = true
				break
			}
		}
		if isDisallowed {
			continue
		}

		// 4. Filtra por subdomínios de CDN/imagens.
		for _, sub := range disallowedHostSubstrings {
			if strings.HasPrefix(lowerHost, sub) {
				isDisallowed = true
				break
			}
		}

		// 5. Adiciona o filtro para as URLs malformadas do paramspider.
		if strings.Contains(cleanedLine, "pagina-nao-encontrada") {
			isDisallowed = true
		}

		if !isDisallowed {
			filteredURLs[cleanedLine] = struct{}{}
		}
	}

	return WriteLines(outputFile, filteredURLs)
}
