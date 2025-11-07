package analysis

import (
	"bufio"
	"encoding/json"
	"os"
	"log/slog"

	"redrecon/pkg/types"
)

func ParseBBot(ndjsonFile string, logger *slog.Logger) ([]types.BBotFinding, error) {
	f, err := os.Open(ndjsonFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var findings []types.BBotFinding
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		var raw map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			logger.Error("Failed to unmarshal BBot JSON line", "file", ndjsonFile, "line", lineNum, "error", err)
			// Continue processing other lines, but log the error
			continue
		}
		f := types.BBotFinding{
			Type:     get(raw, "type"),
			Host:     get(raw, "host"),
			URL:      get(raw, "url"),
			Severity: get(raw, "severity"),
			Data:     raw["data"],
		}
		findings = append(findings, f)
	}
	return findings, scanner.Err()
}

func get(m map[string]interface{}, k string) string {
	if v, ok := m[k].(string); ok {
		return v
	}
	return ""
}