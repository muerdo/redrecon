package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"redrecon/pkg/analysis"
	"redrecon/pkg/types"
	"strings"
)

func parseResults(resultsDir string) ([]Vulnerability, []Asset, error) {
	var vulns []Vulnerability
	var assets []Asset

	// 1. Parse Nuclei Results
	nucleiFile := filepath.Join(resultsDir, "nuclei_scan.json")
	if _, err := os.Stat(nucleiFile); err == nil {
		nucleiVulns, err := parseNuclei(nucleiFile)
		if err == nil {
			vulns = append(vulns, nucleiVulns...)
		}
	}

	// 2. Parse Httpx Results (Assets)
	// httpxFile := filepath.Join(resultsDir, "live", "httpx_live.txt") // Or json if available
	// Check if there is a JSON output for httpx, usually it is better for parsing
	// Assuming we might have httpx_live.json if configured, otherwise parse txt
	// For now, let's look for tech.json which contains tech detection
	techFile := filepath.Join(resultsDir, "tech", "tech.json")
	if _, err := os.Stat(techFile); err == nil {
		httpxAssets, err := parseHttpx(techFile)
		if err == nil {
			assets = append(assets, httpxAssets...)
		}
	}

	// 3. Parse Feroxbuster Results
	feroxFile := filepath.Join(resultsDir, "feroxbuster_scan.txt")
	if _, err := os.Stat(feroxFile); err == nil {
		feroxVulns, err := parseFeroxbuster(feroxFile)
		if err == nil {
			vulns = append(vulns, feroxVulns...)
		}
	}

	// 4. Parse Semgrep Results
	semgrepFile := filepath.Join(resultsDir, "content_analysis", "semgrep_findings.json")
	if _, err := os.Stat(semgrepFile); err == nil {
		semgrepVulns, err := parseSemgrep(semgrepFile)
		if err == nil {
			vulns = append(vulns, semgrepVulns...)
		}
	}

	return vulns, assets, nil
}

func parseNuclei(file string) ([]Vulnerability, error) {
	var vulns []Vulnerability
	// Use existing analysis package if possible, or re-implement simple parsing
	// analysis.ParseNucleiOutput returns []types.NucleiFinding
	// analysis.ParseNuclei returns []types.NucleiFinding
	findings, err := analysis.ParseNuclei(file)
	if err != nil {
		return nil, err
	}

	for _, f := range findings {
		vulns = append(vulns, Vulnerability{
			Title:       f.Meta.Info.Name,
			Severity:    f.Severity,
			Tool:        "Nuclei",
			URL:         f.Target,
			Description: f.Meta.Info.Description,
			Evidence:    f.Timestamp,
		})
	}
	return vulns, nil
}

func parseHttpx(file string) ([]Asset, error) {
	var assets []Asset
	// Httpx JSON output
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		var result types.HttpxResult // Assuming this type exists in pkg/types
		if err := json.Unmarshal([]byte(line), &result); err == nil {
			assets = append(assets, Asset{
				URL:          result.URL,
				IP:           result.Host, // Or IP if available
				Technologies: result.Tech,
				Title:        result.Title,
				StatusCode:   result.StatusCode,
			})
		}
	}
	return assets, nil
}

func parseFeroxbuster(file string) ([]Vulnerability, error) {
	var vulns []Vulnerability
	// Feroxbuster output can be JSON or text. Assuming text for now based on previous steps.
	// If text, it's hard to parse severity.
	// If we changed it to JSON in previous steps, we should parse JSON.
	// Let's assume text for now and treat interesting codes as Info/Low.

	// Actually, let's try to use analysis package if it has Feroxbuster parsing
	// analysis.ParseFeroxbusterOutput

	findings, err := analysis.ParseFeroxbusterResults(file, nil)
	if err != nil {
		return nil, err
	}

	for _, f := range findings {
		vulns = append(vulns, Vulnerability{
			Title:       fmt.Sprintf("Directory Found: %s", f.URL),
			Severity:    "info", // Directories are usually info unless sensitive
			Tool:        "Feroxbuster",
			URL:         f.URL,
			Description: fmt.Sprintf("Status: %d, Size: %d", f.StatusCode, f.Length),
			Evidence:    f.URL,
		})
	}
	return vulns, nil
}

func parseSemgrep(file string) ([]Vulnerability, error) {
	var vulns []Vulnerability
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	var results struct {
		Results []struct {
			CheckID string `json:"check_id"`
			Path    string `json:"path"`
			Extra   struct {
				Severity string `json:"severity"`
				Message  string `json:"message"`
			} `json:"extra"`
		} `json:"results"`
	}

	if err := json.Unmarshal(data, &results); err != nil {
		return nil, err
	}

	for _, r := range results.Results {
		vulns = append(vulns, Vulnerability{
			Title:       r.CheckID,
			Severity:    strings.ToLower(r.Extra.Severity), // ERROR, WARNING, INFO
			Tool:        "Semgrep",
			URL:         r.Path,
			Description: r.Extra.Message,
			Evidence:    r.Path,
		})
	}

	return vulns, nil
}
