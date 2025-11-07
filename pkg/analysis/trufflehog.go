package analysis

import (
	"encoding/json"
	"fmt"
	"os"
	"redrecon/pkg/types"
)

// ParseTruffleHog lê JSON do TruffleHog e retorna findings normalizados.
func ParseTruffleHog(filePath string) ([]types.SecretFinding, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        if os.IsNotExist(err) {
            return nil, nil // Se o arquivo não existe, não é um erro, apenas não há segredos.
        }
        return nil, err
    }

    var raw []TruffleHogRaw
    if err := json.Unmarshal(data, &raw); err != nil {
        return nil, fmt.Errorf("failed to unmarshal trufflehog json: %w", err)
    }

    var findings []types.SecretFinding
    for _, r := range raw {
        evidence := "N/A"
        // Extrai o caminho do arquivo e a linha da evidência do git, se disponível.
        if gitMeta, ok := r.SourceMetadata.Data["git"].(map[string]interface{}); ok {
            if file, ok := gitMeta["file"].(string); ok {
                if line, ok := gitMeta["line"].(float64); ok { // JSON decodifica números como float64
                    evidence = fmt.Sprintf("Found in %s at line %d", file, int(line))
                }
            }
        }

        findings = append(findings, types.SecretFinding{
            Type:     r.DetectorType,
            Secret:   r.Raw,
            File:     r.Location.Path,
            Line:     r.Location.Line,
            Severity: "high", // TruffleHog não fornece severidade, então definimos como alta por padrão.
            Evidence: evidence,
            Meta:     r,
        })
    }
    return findings, nil
}

type TruffleHogRaw struct {
    Type           string     `json:"type"`
    Raw            string     `json:"raw"`
    Location       Location   `json:"location"`
    SourceMetadata SourceMeta `json:"source_metadata"`
    Entropy        float64    `json:"entropy"`
    DetectorType   string     `json:"detector_type"`
}

type Location struct {
	Path string `json:"path"`
	Line int    `json:"line"`
}

type SourceMeta struct {
	Data map[string]interface{} `json:"data"`
}
