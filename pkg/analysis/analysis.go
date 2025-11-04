package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

// HttpxVulnerabilityFinding represents a finding from httpx's vulnerability tests.
type HttpxVulnerabilityFinding struct {
	URL  string
	Type string // e.g., "XSS", "SQLi", "CRLF", "Potential Vulnerability"
}

// NiktoFinding represents a finding from Nikto.
type NiktoFinding struct {
	Host     string
	Message  string
	Severity string // e.g., "VULNERABILITY", "WARNING", "NOTE"
}

// FfufJSONResult is a simplified struct for parsing ffuf's JSON output lines.
type FfufJSONResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status"`
	Length     int    `json:"length"`
	Words      int    `json:"words"`
	Lines      int    `json:"lines"`
	Redirect   string `json:"redirectlocation"`
}

// FfufFinding represents an interesting finding from ffuf.
type FfufFinding struct {
	URL        string
	StatusCode int
	Length     int
	Words      int
	Lines      int
	Redirect   string // If it's a redirect
}

// DirsearchJSONResult is a simplified struct for parsing dirsearch's JSON output.
type DirsearchJSONResult struct {
	URL           string `json:"url"`
	Path          string `json:"path"`
	StatusCode    int    `json:"status"`
	ContentLength int    `json:"content_length"`
	Redirect      string `json:"redirect"`
}

// DirsearchFinding represents an interesting finding from dirsearch.
type DirsearchFinding struct {
	URL        string
	StatusCode int
	Length     int
	Redirect   string
}

// ParseNucleiResults reads and parses Nuclei JSON output.
func ParseNucleiResults(filePath string, logger *slog.Logger) ([]types.NucleiFinding, error) {
	if !utils.FileExistsAndIsNotEmpty(filePath) {
		return nil, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Nuclei results file %s: %w", filePath, err)
	}
	defer file.Close()

	var findings []types.NucleiFinding
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var finding types.NucleiFinding
		if err := json.Unmarshal(scanner.Bytes(), &finding); err != nil {
			logger.Warn("Failed to unmarshal Nuclei finding, skipping line", "error", err, "line", scanner.Text())
			continue
		}
		findings = append(findings, finding)
	}
	return findings, scanner.Err()
}

// ParseHttpxVulnerabilityResults reads and parses httpx vulnerability output.
func ParseHttpxVulnerabilityResults(filePath string, logger *slog.Logger) ([]HttpxVulnerabilityFinding, error) {
	if !utils.FileExistsAndIsNotEmpty(filePath) {
		return nil, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open httpx vulnerability results file %s: %w", filePath, err)
	}
	defer file.Close()

	var findings []HttpxVulnerabilityFinding
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// httpx output for vulns is usually just the URL if a vuln is found.
		// We infer the type as "Potential Vulnerability" for now.
		findings = append(findings, HttpxVulnerabilityFinding{URL: line, Type: "Potential Vulnerability"})
	}
	return findings, scanner.Err()
}

// ParseNiktoResults reads and parses Nikto text output.
func ParseNiktoResults(filePath string, logger *slog.Logger) ([]NiktoFinding, error) {
	if !utils.FileExistsAndIsNotEmpty(filePath) {
		return nil, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open Nikto results file %s: %w", filePath, err)
	}
	defer file.Close()

	var findings []NiktoFinding
	scanner := bufio.NewScanner(file)
	currentHost := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "--- Nikto Scan for ") {
			parts := strings.Split(line, " ")
			if len(parts) > 4 {
				currentHost = parts[4] // Extract host from "--- Nikto Scan for HOST ---"
			}
			continue
		}
		if strings.HasPrefix(line, "+") || strings.HasPrefix(line, "!") {
			severity := "NOTE"
			if strings.HasPrefix(line, "+") {
				severity = "VULNERABILITY"
			} else if strings.HasPrefix(line, "!") {
				severity = "WARNING"
			}

			findings = append(findings, NiktoFinding{
				Host:     currentHost,
				Message:  strings.TrimPrefix(line, "+ "),
				Severity: severity,
			})
		}
	}
	return findings, scanner.Err()
}

// ParseFfufResults reads and parses ffuf JSON output files from a directory.
func ParseFfufResults(outputDir string, logger *slog.Logger) ([]FfufFinding, error) {
	if !utils.DirExistsAndIsNotEmpty(outputDir) {
		return nil, nil
	}

	var allFindings []FfufFinding
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Warn("Error walking ffuf results directory", "path", path, "error", err)
			return nil // Continue walking
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			logger.Warn("Failed to open ffuf result file", "path", path, "error", err)
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var result FfufJSONResult
			if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
				logger.Warn("Failed to unmarshal ffuf JSON line", "path", path, "error", err, "line", scanner.Text())
				continue
			}

			// Filter for interesting findings (e.g., 200 OK on unexpected paths, or redirects)
			if result.StatusCode >= 200 && result.StatusCode < 300 && result.Length > 0 && result.URL != "" {
				allFindings = append(allFindings, FfufFinding{
					URL:        result.URL,
					StatusCode: result.StatusCode,
					Length:     result.Length,
					Words:      result.Words,
					Lines:      result.Lines,
					Redirect:   result.Redirect,
				})
			} else if result.StatusCode >= 300 && result.StatusCode < 400 && result.Redirect != "" {
				allFindings = append(allFindings, FfufFinding{
					URL:        result.URL,
					StatusCode: result.StatusCode,
					Redirect:   result.Redirect,
				})
			}
		}
		return scanner.Err()
	})
	return allFindings, err
}

// ParseDirsearchResults reads and parses dirsearch JSON output files from a directory.
func ParseDirsearchResults(outputDir string, logger *slog.Logger) ([]DirsearchFinding, error) {
	if !utils.DirExistsAndIsNotEmpty(outputDir) {
		return nil, nil
	}

	var allFindings []DirsearchFinding
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Warn("Error walking dirsearch results directory", "path", path, "error", err)
			return nil // Continue walking
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			logger.Warn("Failed to open dirsearch result file", "path", path, "error", err)
			return nil
		}
		defer file.Close()

		var results []DirsearchJSONResult
		if err := json.NewDecoder(file).Decode(&results); err != nil {
			logger.Warn("Failed to unmarshal dirsearch JSON file", "path", path, "error", err)
			return nil
		}

		for _, result := range results {
			if result.StatusCode >= 200 && result.StatusCode < 300 && result.ContentLength > 0 && result.URL != "" {
				allFindings = append(allFindings, DirsearchFinding{
					URL:        result.URL,
					StatusCode: result.StatusCode,
					Length:     result.ContentLength,
					Redirect:   result.Redirect,
				})
			} else if result.StatusCode >= 300 && result.StatusCode < 400 && result.Redirect != "" {
				allFindings = append(allFindings, DirsearchFinding{
					URL:        result.URL,
					StatusCode: result.StatusCode,
					Redirect:   result.Redirect,
				})
			}
		}
		return nil
	})
	return allFindings, err
}

// ParseURLFindings reads and parses URLFindings (secrets/endpoints) from a file.
// It expects each line of the file to be a self-contained JSON object.
func ParseURLFindings(filePath string, logger *slog.Logger) ([]types.URLFindings, error) {
	if !utils.FileExistsAndIsNotEmpty(filePath) {
		return nil, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open URL findings file %s: %w", filePath, err)
	}
	defer file.Close()

	var allFindings []types.URLFindings
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var finding types.URLFindings
		if err := json.Unmarshal(scanner.Bytes(), &finding); err != nil {
			logger.Warn("Failed to unmarshal URL finding, skipping line", "error", err, "line", scanner.Text())
			continue
		}
		allFindings = append(allFindings, finding)
	}

	return allFindings, scanner.Err()
}

// ParseCVEResults reads and parses CVE results JSON output.
func ParseCVEResults(filePath string, logger *slog.Logger) ([]types.CVEResult, error) {
	if !utils.FileExistsAndIsNotEmpty(filePath) {
		return nil, nil
	}
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open CVE results file %s: %w", filePath, err)
	}
	defer file.Close()

	var results []types.CVEResult
	if err := json.NewDecoder(file).Decode(&results); err != nil {
		logger.Warn("Failed to unmarshal CVE results JSON", "error", err, "file", filePath)
		return nil, err
	}
	return results, nil
}