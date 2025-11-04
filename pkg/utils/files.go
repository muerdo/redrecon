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

func CombineAndDeduplicateFiles(destFile string, sources ...string) error {
	allItems := make(map[string]struct{})

	if FileExistsAndIsNotEmpty(destFile) {
		existingItems, err := ReadLines(destFile)
		if err != nil {
			return fmt.Errorf("error reading existing destination file: %w", err)
		}
		for _, item := range existingItems {
			allItems[item] = struct{}{}
		}
	}

	for _, src := range sources {
		if src == "" {
			continue
		}

		if FileExistsAndIsNotEmpty(src) {
			lines, err := ReadLines(src)
			if err != nil {
				slog.Warn("Could not read source file during combination, skipping.", "file", src, "error", err)
				continue
			}
			for _, line := range lines {
				allItems[line] = struct{}{}
			}
		} else {
			scanner := bufio.NewScanner(strings.NewReader(src))
			for scanner.Scan() {
				cleanItem := strings.TrimSpace(scanner.Text())
				if cleanItem != "" {
					allItems[cleanItem] = struct{}{}
				}
			}
		}
	}

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

		if strings.HasPrefix(trimmedLine, "http://") || strings.HasPrefix(trimmedLine, "https://") {
			validURLs[trimmedLine] = struct{}{}
			continue
		}

		validURLs["http://"+trimmedLine] = struct{}{}
		validURLs["https://"+trimmedLine] = struct{}{}
	}

	if len(validURLs) == 0 {
		return inputFile, nil
	}

	tempFile, err := os.CreateTemp(tempDir, "httpx_processed_*.txt")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file for processed URLs: %w", err)
	}
	defer tempFile.Close()

	return tempFile.Name(), WriteLines(tempFile.Name(), validURLs)
}

func FilterScanTargets(inputFile, outputFile string, logger *slog.Logger) error {
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

	disallowedHostSubstrings := []string{
		"images.", "img.", "cdn.", "assets.", "static.",
	}

	urlCleanerRegex := regexp.MustCompile(`^https?:\/\/[^\s"']*[^\s"'.:,]`)

	lines, err := ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file for filtering: %w", err)
	}

	filteredURLs := make(map[string]struct{})
	for _, line := range lines {
		cleanedLine := urlCleanerRegex.FindString(line)
		if cleanedLine == "" {
			continue
		}

		parsedURL, err := url.Parse(cleanedLine)
		if err != nil || parsedURL.Scheme == "" || parsedURL.Host == "" {
			continue
		}

		lowerPath := strings.ToLower(parsedURL.Path)
		lowerHost := strings.ToLower(parsedURL.Host)
		isDisallowed := false

		for _, ext := range disallowedExtensions {
			if strings.HasSuffix(lowerPath, ext) {
				isDisallowed = true
				break
			}
		}
		if isDisallowed {
			continue
		}

		for _, sub := range disallowedHostSubstrings {
			if strings.HasPrefix(lowerHost, sub) {
				isDisallowed = true
				break
			}
		}

		if strings.Contains(cleanedLine, "pagina-nao-encontrada") {
			isDisallowed = true
		}

		if !isDisallowed {
			filteredURLs[cleanedLine] = struct{}{}
		}
	}

	return WriteLines(outputFile, filteredURLs)
}
