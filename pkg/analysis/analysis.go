package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"net/url" // Adicionado: Importa o pacote net/url

	"redrecon/internal/config"
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

// FeroxbusterJSONResult é uma struct simplificada para o parsing da saída JSON do feroxbuster.
type FeroxbusterJSONResult struct {
	URL        string `json:"url"`
	StatusCode int    `json:"status"`
	Length     int    `json:"content_length"`
	Redirect   string `json:"redirect_location"`
}

// FeroxbusterFinding representa uma descoberta interessante do feroxbuster.
type FeroxbusterFinding struct {
	URL        string
	StatusCode int
	Length     int
	Redirect   string
}

// GobusterFinding representa uma descoberta interessante do gobuster.
type GobusterFinding struct {
	URL        string
	Path       string
	StatusCode int
}

// ParseNucleiResults reads and parses Nuclei JSON output.
func ParseNuclei(filePath string) ([]types.NucleiFinding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []types.NucleiFinding
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var raw types.NucleiRawOutput
		if err := json.Unmarshal(line, &raw); err != nil {
			continue  // Tolerante a linhas inválidas
		}

		finding := types.NucleiFinding{
			ID:        fmt.Sprintf("%s|%s", raw.TemplateID, raw.Host),
			Tool:      "nuclei",
			Target:    raw.Host,
			Severity:  raw.Info.Severity,
			Timestamp: raw.MatchedAt,
			Meta:      raw,
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

// ParseFeroxbusterResults lê e faz o parsing dos arquivos de saída JSON do feroxbuster de um diretório.
func ParseFeroxbusterResults(outputDir string, logger *slog.Logger) ([]FeroxbusterFinding, error) {
	if !utils.DirExistsAndIsNotEmpty(outputDir) {
		return nil, nil
	}

	var allFindings []FeroxbusterFinding
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Warn("Error walking feroxbuster results directory", "path", path, "error", err)
			return nil // Continue walking
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".json") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			logger.Warn("Failed to open feroxbuster result file", "path", path, "error", err)
			return nil
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			var result FeroxbusterJSONResult
			if err := json.Unmarshal(scanner.Bytes(), &result); err != nil {
				logger.Warn("Failed to unmarshal feroxbuster JSON line", "path", path, "error", err, "line", scanner.Text())
				continue
			}

			if (result.StatusCode >= 200 && result.StatusCode < 300 && result.Length > 0) || (result.StatusCode >= 300 && result.StatusCode < 400 && result.Redirect != "") {
				allFindings = append(allFindings, FeroxbusterFinding{
					URL:        result.URL,
					StatusCode: result.StatusCode,
					Length:     result.Length,
					Redirect:   result.Redirect,
				})
			}
		}
		return scanner.Err()
	})
	return allFindings, err
}

// ParseGobusterResults lê e faz o parsing dos arquivos de saída de texto do gobuster de um diretório.
func ParseGobusterResults(outputDir string, logger *slog.Logger) ([]GobusterFinding, error) {
	if !utils.DirExistsAndIsNotEmpty(outputDir) {
		return nil, nil
	}

	var allFindings []GobusterFinding
	err := filepath.Walk(outputDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Warn("Error walking gobuster results directory", "path", path, "error", err)
			return nil // Continue walking
		}
		if info.IsDir() || !strings.HasSuffix(info.Name(), ".txt") {
			return nil
		}

		file, err := os.Open(path)
		if err != nil {
			logger.Warn("Failed to open gobuster result file", "path", path, "error", err)
			return nil
		}
		defer file.Close()

		// Read the host mapping file
		mappingFile := filepath.Join(outputDir, "gobuster_host_map.json")
		hostMappings := make(map[string]string)
		if utils.FileExistsAndIsNotEmpty(mappingFile) {
			mapBytes, readErr := os.ReadFile(mappingFile)
			if readErr != nil {
				logger.Warn("Failed to read gobuster host map file", "path", mappingFile, "error", readErr)
			} else {
				if unmarshalErr := json.Unmarshal(mapBytes, &hostMappings); unmarshalErr != nil {
					logger.Warn("Failed to unmarshal gobuster host map", "path", mappingFile, "error", unmarshalErr)
				}
			}
		}

		// Extract the sanitized filename part from the current result file
		sanitizedFilenamePart := strings.TrimSuffix(info.Name(), ".txt")
		originalTargetURL, found := hostMappings[sanitizedFilenamePart]
		if !found {
			logger.Warn("Original URL not found in mapping for gobuster result file, falling back to HTTPS assumption.", "file", info.Name())
			originalTargetURL = "https://" + strings.ReplaceAll(sanitizedFilenamePart, "_", "/") // Fallback
		}

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Fields(line)
			// Exemplo de linha: /path (Status: 301)
			if len(parts) >= 3 && strings.HasPrefix(parts[1], "(Status:") {
				foundPath := parts[0]
				statusCodeStr := strings.TrimSuffix(strings.TrimPrefix(parts[2], ":"), ")")
				statusCode := 0
				fmt.Sscanf(statusCodeStr, "%d", &statusCode)

				if statusCode > 0 {
					fullURL, urlErr := url.JoinPath(originalTargetURL, foundPath)
					if urlErr != nil {
						logger.Warn("Failed to join URL for gobuster finding", "base", originalTargetURL, "path", foundPath)
						continue
					}
					allFindings = append(allFindings, GobusterFinding{
						URL:        fullURL,
						Path:       foundPath,
						StatusCode: statusCode,
					})
				}
			}
		}
		return scanner.Err()
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

// MetasploitExploitSuggestion represents a suggestion for a Metasploit exploit.
type MetasploitExploitSuggestion struct {
	VulnerabilityType string
	Target            string
	MetasploitModule  string
	Description       string
	// Add other relevant fields like payload options, RHOSTS, RPORT, etc.
}

// MapFindingsToMetasploitModules maps various findings to potential Metasploit modules.
func MapFindingsToMetasploitModules(nucleiFindings []types.NucleiFinding, logger *slog.Logger) []MetasploitExploitSuggestion {
	var suggestions []MetasploitExploitSuggestion
	vulnerabilityModules := config.Cfg.Metasploit.VulnerabilityModules

	for _, finding := range nucleiFindings {
		// Try to map based on template tags first
		for _, tag := range finding.Meta.Info.Tags {
			if modules, ok := vulnerabilityModules[tag]; ok {
				for _, module := range modules {
					suggestions = append(suggestions, MetasploitExploitSuggestion{
						VulnerabilityType: tag,
						Target:            finding.Target,
						MetasploitModule:  module,
						Description:       fmt.Sprintf("Nuclei finding: %s - %s", finding.Meta.Info.Name, finding.Meta.Info.Description),
					})
				}
			}
		}

		// Fallback to mapping based on severity or template name if no tag match
		// This part can be expanded with more sophisticated mapping logic
		if len(finding.Meta.Info.Tags) == 0 { // If no tags, try mapping by severity or name
			// Example: Map high severity findings to a generic exploit category
			if finding.Severity == "critical" || finding.Severity == "high" {
				if modules, ok := vulnerabilityModules["generic_high_severity"]; ok {
					for _, module := range modules {
						suggestions = append(suggestions, MetasploitExploitSuggestion{
							VulnerabilityType: "generic_high_severity",
							Target:            finding.Target,
							MetasploitModule:  module,
							Description:       fmt.Sprintf("Nuclei finding: %s - %s", finding.Meta.Info.Name, finding.Meta.Info.Description),
						})
					}
				}
			}
		}
	}
	return suggestions
}

// GenerateMetasploitRCFile generates an msfconsole resource file (.rc)
// from a list of Metasploit exploit suggestions.
func GenerateMetasploitRCFile(suggestions []MetasploitExploitSuggestion, filePath string, logger *slog.Logger) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create Metasploit RC file %s: %w", filePath, err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	_, err = writer.WriteString("setg RHOSTS\n") // Clear global RHOSTS
	if err != nil {
		return err
	}

	for _, suggestion := range suggestions {
		_, err = writer.WriteString(fmt.Sprintf("use %s\n", suggestion.MetasploitModule))
		if err != nil {
			return err
		}
		// Assuming the target is a URL, extract host
		parsedURL, err := url.Parse(suggestion.Target)
		if err != nil {
			logger.Warn("Failed to parse target URL for Metasploit RC file", "target", suggestion.Target, "error", err)
			continue
		}
		_, err = writer.WriteString(fmt.Sprintf("set RHOSTS %s\n", parsedURL.Hostname()))
		if err != nil {
			return err
		}
		// Add other common options. This can be expanded based on module requirements.
		_, err = writer.WriteString("set LHOST 127.0.0.1\n") // Placeholder, should be configurable
		_, err = writer.WriteString("set LPORT 4444\n")    // Placeholder, should be configurable
		_, err = writer.WriteString("exploit -j -z\n") // Run in background, don't interact
		_, err = writer.WriteString("\n")
		if err != nil {
			return err
		}
	}
	logger.Info("Metasploit RC file generated successfully", "path", filePath)
	return nil
}