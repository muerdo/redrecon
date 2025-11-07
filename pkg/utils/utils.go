package utils

import (
	"encoding/json"
	"io"
	"os"
	"net"
	"strings"
)

// FileExistsAndIsNotEmpty checks if a file exists and is not empty.
// This function is assumed to be needed based on its usage in steps_nuclei.go
func FileExistsAndIsNotEmpty(filePath string) bool {
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && info.Size() > 0
}

// WriteJSON writes data to a file in JSON format.
func WriteJSON(filePath string, data interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Para formatação legível
	return encoder.Encode(data)
}

// WriteLines writes a slice of strings to a file, each on a new line.
func WriteLines(filePath string, lines []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

// Contains checks if a string slice contains um item específico (correspondência de substring sem distinção entre maiúsculas e minúsculas).
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		// Usando strings.Contains para correspondência de substring, conforme implícito pela função 'contains' original
		// Se for necessária uma correspondência exata, altere para `s == item`
		if strings.Contains(s, item) {
			return true
		}
	}
	return false
}

var pathSanitizer = strings.NewReplacer(
	"/", "_",
	"\\", "_",
	":", "_",
	"*", "_",
	"?", "_",
	"\"", "_",
	"<", "_",
	">", "_",
	"|", "_",
)

// SanitizeTargetForPath substitui caracteres inválidos em nomes de arquivo/caminho.
func SanitizeTargetForPath(target string) string {
	return pathSanitizer.Replace(target)
}

// DirExistsAndIsNotEmpty verifica se um diretório existe e não está vazio.
func DirExistsAndIsNotEmpty(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) || !info.IsDir() {
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	_, err = f.Readdirnames(1) // Tenta ler pelo menos uma entrada.
	return err != io.EOF
}

// FIX: Adicionando IsValidIP ao pacote utils para reuso em outros pacotes.
// IsValidIP verifica se uma string é um endereço IP válido.
func IsValidIP(address string) bool {
	parsedIP := net.ParseIP(address)
	return parsedIP != nil
}