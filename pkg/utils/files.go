package utils

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"strings"
)

// AppendAndDeduplicate lê o conteúdo de um arquivo, adiciona novas linhas,
// remove duplicatas e reescreve o arquivo.
func AppendAndDeduplicate(filePath string, newLines ...string) error {
	existingLines := make(map[string]struct{})

	// Lê as linhas existentes, se o arquivo existir
	if FileExistsAndIsNotEmpty(filePath) {
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				existingLines[line] = struct{}{}
			}
		}
		file.Close()
	}

	// Adiciona novas linhas
	for _, line := range newLines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine != "" {
			existingLines[trimmedLine] = struct{}{}
		}
	}

	// Converte o mapa de volta para um slice de strings e escreve no arquivo
	var allLines []string
	for line := range existingLines {
		allLines = append(allLines, line)
	}

	return os.WriteFile(filePath, []byte(strings.Join(allLines, "\n")), 0644)
}

// CountLines conta o número de linhas não vazias em um arquivo.
func CountLines(filePath string) int {
	if !FileExistsAndIsNotEmpty(filePath) {
		return 0
	}
	file, err := os.Open(filePath)
	if err != nil {
		return 0
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) != "" {
			count++
		}
	}
	return count
}

// CombineAndDeduplicateFiles lê múltiplos arquivos de origem e/ou conteúdos de string,
// combina todas as linhas, remove duplicatas e escreve o resultado em um arquivo de destino.
func CombineAndDeduplicateFiles(destinationFile string, sources ...string) error {
	uniqueLines := make(map[string]struct{})

	// Processa cada fonte (que pode ser um caminho de arquivo ou conteúdo de string)
	for _, source := range sources {
		// Tenta tratar a fonte como um caminho de arquivo primeiro
		if _, err := os.Stat(source); err == nil {
			file, err := os.Open(source)
			if err != nil {
				// Se não conseguir abrir o arquivo, registra um aviso e continua.
				// Não trata o caminho como conteúdo.
				slog.Warn("CombineAndDeduplicateFiles: could not open source file, skipping", "file", source, "error", err)
				continue
			}

			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					uniqueLines[line] = struct{}{}
				}
			}
			_ = file.Close() // Ignora o erro no close, pois estamos lendo
		} else { // Se não for um caminho de arquivo, trata como conteúdo de string literal
			// Divide o conteúdo em linhas
			for _, line := range strings.Split(source, "\n") {
				trimmedLine := strings.TrimSpace(line)
				if trimmedLine != "" {
					uniqueLines[trimmedLine] = struct{}{}
				}
			}
		}
	}

	var allLines []string
	for line := range uniqueLines {
		allLines = append(allLines, line)
	}

	return os.WriteFile(destinationFile, []byte(strings.Join(allLines, "\n")+"\n"), 0644)
}

// FilterScanTargets lê um arquivo de entrada, remove URLs que correspondem a extensões de arquivo indesejadas
// e escreve as URLs restantes em um arquivo de saída.
func FilterScanTargets(inputFile, outputFile string, logger *slog.Logger) error {
	input, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("failed to open input file for filtering: %w", err)
	}
	defer input.Close()

	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file for filtering: %w", err)
	}
	defer output.Close()

	// Lista de extensões de arquivo a serem ignoradas (case-insensitive)
	ignoredExtensions := []string{
		".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
		".woff", ".woff2", ".ttf", ".eot", ".otf",
		".js", // JS é frequentemente analisado em outras etapas, pode ser filtrado aqui para evitar ruído no scan.
	}

	writer := bufio.NewWriter(output)
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lowerLine := strings.ToLower(line)
		shouldKeep := true
		for _, ext := range ignoredExtensions {
			if strings.HasSuffix(lowerLine, ext) {
				shouldKeep = false
				break
			}
		}
		if shouldKeep && line != "" {
			_, _ = writer.WriteString(line + "\n")
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input file during filtering: %w", err)
	}

	return writer.Flush()
}

// ReadLines lê todas as linhas de um arquivo e as retorna como um slice de strings.
func ReadLines(filePath string) ([]string, error) {
	if !FileExistsAndIsNotEmpty(filePath) {
		return nil, nil // Retorna nil se o arquivo não existir ou estiver vazio
	}

	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file %s: %w", filePath, err)
	}

	return lines, nil
}

// CopyFile copia o conteúdo de um arquivo de origem para um arquivo de destino.
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dst, err)
	}
	defer destFile.Close()

	_, err = sourceFile.WriteTo(destFile)
	if err != nil {
		return fmt.Errorf("failed to write to destination file %s: %w", dst, err)
	}

	return nil
}

// WriteTempLines cria um arquivo temporário com o conteúdo fornecido.
func WriteTempLines(lines map[string]struct{}, tempDir, pattern string) (string, error) {
	// Implementação baseada no uso em recon.go
	// Converte o mapa para um slice
	var lineSlice []string
	for line := range lines {
		lineSlice = append(lineSlice, line)
	}

	tmpFile, err := os.CreateTemp(tempDir, pattern)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer tmpFile.Close()

	_, err = tmpFile.WriteString(strings.Join(lineSlice, "\n"))
	if err != nil {
		return "", fmt.Errorf("failed to write to temporary file: %w", err)
	}

	return tmpFile.Name(), nil
}

// UniqueStrings remove strings duplicadas de um slice.
func UniqueStrings(slice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// DiffFiles compara dois arquivos e retorna as linhas que estão no segundo arquivo mas não no primeiro.
func DiffFiles(file1, file2 string) ([]string, error) {
	lines1 := make(map[string]struct{})

	// Lê as linhas do primeiro arquivo
	if FileExistsAndIsNotEmpty(file1) {
		f1, err := os.Open(file1)
		if err != nil {
			return nil, fmt.Errorf("failed to open first file for diff: %w", err)
		}
		defer f1.Close()
		scanner1 := bufio.NewScanner(f1)
		for scanner1.Scan() {
			lines1[scanner1.Text()] = struct{}{}
		}
		if err := scanner1.Err(); err != nil {
			return nil, fmt.Errorf("error reading first file for diff: %w", err)
		}
	}

	// Lê o segundo arquivo e encontra as diferenças
	var diffs []string
	f2, err := os.Open(file2)
	if err != nil {
		return nil, fmt.Errorf("failed to open second file for diff: %w", err)
	}
	defer f2.Close()
	scanner2 := bufio.NewScanner(f2)
	for scanner2.Scan() {
		line := scanner2.Text()
		if _, exists := lines1[line]; !exists {
			diffs = append(diffs, line)
		}
	}

	return diffs, scanner2.Err()
}

// AppendFile anexa o conteúdo de um arquivo de origem a um arquivo de destino.
// Se o arquivo de destino não existir, ele será criado.
func AppendFile(dest, src string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file for appending: %w", err)
	}
	defer sourceFile.Close()

	destFile, err := os.OpenFile(dest, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open destination file for appending: %w", err)
	}
	defer destFile.Close()

	scanner := bufio.NewScanner(sourceFile)
	for scanner.Scan() {
		if _, err := destFile.WriteString(scanner.Text() + "\n"); err != nil {
			return fmt.Errorf("failed to write to destination file during append: %w", err)
		}
	}
	return scanner.Err()
}

// PrepareTargetsFile takes a target string (which can be a file path or a single target like a URL/IP)
// and a temporary directory. If the target string is an existing file, its path is returned.
// Otherwise, the target string is written to a new temporary file in tempDir, and the path to this
// temporary file is returned. This ensures that tools expecting a file of targets always receive one.
func PrepareTargetsFile(targetInput string, tempDir string) (string, error) {
	// Check if targetInput is an existing file
	if FileExistsAndIsNotEmpty(targetInput) {
		return targetInput, nil
	}

	// Assume targetInput is a single target (URL, IP, etc.)
	// Write it to a temporary file
	tmpFile, err := os.CreateTemp(tempDir, "nuclei_target_*.txt")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary target file: %w", err)
	}
	defer tmpFile.Close() // Close the file, but don't remove it here. It will be removed by the caller or at the end of the process.

	if _, err := tmpFile.WriteString(targetInput + "\n"); err != nil {
		os.Remove(tmpFile.Name()) // Clean up if write fails
		return "", fmt.Errorf("failed to write target to temporary file: %w", err)
	}

	return tmpFile.Name(), nil
}
