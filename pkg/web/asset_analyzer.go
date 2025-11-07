package web

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// AnalyzeJSFiles searches for potential API endpoints in JavaScript files
// within a given directory, saves them to a file, and returns them.
func AnalyzeJSFiles(resultsDir string) ([]string, error) {
	slog.Info("Starting JavaScript analysis for API endpoints", "directory", resultsDir)

	// Regex to find paths. It looks for strings like "/api/v1/users" or "/_next/data/..."
	// It captures path-like strings starting with a slash.
	pathRegex := regexp.MustCompile(`['"](\/[a-zA-Z0-9\/_-]{3,})['"]`)

	endpoints := make(map[string]struct{})

	walkErr := filepath.WalkDir(resultsDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".js") {
			slog.Debug("Analyzing JS file", "path", path)
			content, err := os.ReadFile(path)
			if err != nil {
				slog.Warn("Failed to read JS file", "path", path, "error", err)
				return nil // Continue to the next file
			}

			matches := pathRegex.FindAllStringSubmatch(string(content), -1)
			for _, match := range matches {
				if len(match) > 1 {
					// The first capture group is our endpoint
					endpoint := match[1]
					// Basic filtering to reduce noise
					if !strings.HasSuffix(endpoint, ".js") && !strings.HasSuffix(endpoint, ".css") {
						endpoints[endpoint] = struct{}{}
					}
				}
			}
		}
		return nil
	})

	if walkErr != nil {
		return nil, fmt.Errorf("error walking directory for JS analysis: %w", walkErr)
	}

	// Convert map keys to a slice for sorting and returning
	uniqueEndpoints := make([]string, 0, len(endpoints))
	for endpoint := range endpoints {
		uniqueEndpoints = append(uniqueEndpoints, endpoint)
	}
	sort.Strings(uniqueEndpoints) // Sort for consistent output

	if len(uniqueEndpoints) > 0 {
		slog.Info("Found potential API endpoints", "count", len(uniqueEndpoints))
		// Save endpoints to a file
		outputFile := filepath.Join(resultsDir, "endpoints.txt")
		file, err := os.Create(outputFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create endpoints file: %w", err)
		}
		defer file.Close()

		for _, endpoint := range uniqueEndpoints {
			fmt.Fprintln(file, endpoint)
		}
		slog.Info("Endpoints saved", "file", outputFile)
	} else {
		slog.Info("No potential API endpoints found in JavaScript files.")
	}

	return uniqueEndpoints, nil
}
