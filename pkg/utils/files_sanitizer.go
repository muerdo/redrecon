package utils

import "strings"

// SanitizeAndCombineReconTargets combines files and filters out DNS info and file paths.
func SanitizeAndCombineReconTargets(outputFile string, inputFiles ...string) error {
	uniqueLines := make(map[string]struct{})

	for _, file := range inputFiles {
		if !FileExistsAndIsNotEmpty(file) {
			continue
		}
		lines, err := ReadLines(file)
		if err != nil {
			return err
		}
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			// Filter out DNS info (contains "-->")
			if strings.Contains(line, "-->") {
				continue
			}
			// Filter out file paths (e.g., starts with "results/")
			if strings.HasPrefix(line, "results/") {
				continue
			}
			uniqueLines[line] = struct{}{}
		}
	}

	var result []string
	for line := range uniqueLines {
		result = append(result, line)
	}

	return WriteLines(outputFile, result)
}
