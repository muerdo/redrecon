package utils

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// CopyFile copies a file from src to dst.
func CopyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", src, err)
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", dst, err)
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	if err != nil {
		return fmt.Errorf("failed to copy file from %s to %s: %w", src, dst, err)
	}

	return nil
}

// FileExistsAndIsNotEmpty verifica se um arquivo existe e não está vazio.
func FileExistsAndIsNotEmpty(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return false // Outro erro, como permissão negada.
	}
	return !info.IsDir() && info.Size() > 0
}

// DirExistsAndIsNotEmpty verifica se um diretório existe e não está vazio.
func DirExistsAndIsNotEmpty(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	if err != nil {
		return false
	}
	if !info.IsDir() {
		return false
	}

	// Tenta ler o conteúdo do diretório.
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	// Tenta ler apenas uma entrada. Se conseguir, o diretório não está vazio.
	_, err = f.Readdirnames(1)
	return err == nil
}

// ReadLines lê um arquivo inteiro em memória e retorna um slice de suas linhas.
func ReadLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

// WriteTempLines cria um arquivo temporário com o conteúdo de um mapa de strings.
func WriteTempLines(lines map[string]struct{}, tempDir, pattern string) (string, error) {
	tempFile, err := os.CreateTemp(tempDir, pattern)
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer tempFile.Close()

	writer := bufio.NewWriter(tempFile)
	for line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return "", fmt.Errorf("failed to write to temporary file: %w", err)
		}
	}
	if err := writer.Flush(); err != nil {
		return "", fmt.Errorf("failed to flush temporary file: %w", err)
	}

	return tempFile.Name(), nil
}

// CommandExists verifica se um comando existe no PATH do sistema.
func CommandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// ExecuteCommand executa um comando externo e retorna sua saída padrão.
func ExecuteCommand(ctx context.Context, logger *slog.Logger, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	if err != nil {
		// Se o contexto foi cancelado, o erro é esperado.
		if ctx.Err() == context.Canceled {
			logger.Warn("Command execution cancelled", "command", name, "duration", duration.Seconds())
			return stdout.String(), ctx.Err()
		}
		// Loga o erro com mais detalhes para depuração.
		errorMsg := fmt.Sprintf("command '%s %s' failed after %.2fs: %v. Stderr: %s", name, strings.Join(args, " "), duration.Seconds(), err, stderr.String())
		logger.Debug(errorMsg) // Usa Debug para não poluir o log principal com erros esperados de ferramentas.
		return stdout.String(), fmt.Errorf(errorMsg)
	}

	logger.Debug("Command executed successfully", "command", name, "duration", duration.Seconds())
	return stdout.String(), nil
}

// SanitizeTargetForPath remove caracteres inválidos de um nome de alvo para usá-lo como um caminho de arquivo.
func SanitizeTargetForPath(target string) string {
	// Remove o esquema (http://, https://)
	re := regexp.MustCompile(`^https?:\/\/`)
	sanitized := re.ReplaceAllString(target, "")
	// Substitui caracteres inválidos para nomes de arquivo/diretório por underscores.
	re = regexp.MustCompile(`[\\/:*?"<>|]`)
	sanitized = re.ReplaceAllString(sanitized, "_")
	return sanitized
}

// PreprocessForHttpxProbe lê um arquivo de entrada, extrai apenas os hostnames (removendo esquemas e portas)
// e salva os hostnames únicos em um novo arquivo temporário.
// Isso é útil para preparar uma lista de alvos para o httpx com as flags -probe e -ports.
func PreprocessForHttpxProbe(inputFile, tempDir string, logger *slog.Logger) (string, error) {
	if !FileExistsAndIsNotEmpty(inputFile) {
		return "", fmt.Errorf("input file does not exist or is empty: %s", inputFile)
	}

	content, err := os.ReadFile(inputFile)
	if err != nil {
		return "", fmt.Errorf("failed to read input file for preprocessing: %w", err)
	}

	uniqueHosts := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Remove o esquema se presente
		if i := strings.Index(line, "://"); i != -1 {
			line = line[i+3:]
		}

		// Remove a porta se presente
		host, _, err := net.SplitHostPort(line)
		if err == nil {
			line = host
		}

		if line != "" {
			uniqueHosts[line] = struct{}{}
		}
	}

	return WriteTempLines(uniqueHosts, tempDir, "httpx_probe_targets_*.txt")
}