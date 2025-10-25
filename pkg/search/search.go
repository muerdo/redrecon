package search

import (
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/logrusorgru/aurora"
)

// StartSearch initiates a search for a term in the results directory.
func StartSearch(searchTerm, target string, contextLines int, useRegex bool, filesWithMatches bool) error {
	searchPath := "results"
	if target != "" {
		searchPath = filepath.Join(searchPath, target)
	}

	au := aurora.NewAurora(true)

	return filepath.WalkDir(searchPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil // Skip directories
		}

		// We use a helper function to process each file.
		return processFile(path, searchTerm, contextLines, useRegex, filesWithMatches, au)
	})
}

// processFile reads a file and searches for the term, printing matches with context.
func processFile(filePath, searchTerm string, contextLines int, useRegex bool, filesWithMatches bool, au aurora.Aurora) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		// Return nil to continue walking files, but log the error.
		slog.Warn("Could not read file, skipping", "path", filePath, "error", err)
		return nil
	}

	// Split the content into lines. This is more robust than bufio.Scanner for long lines.
	lines := strings.Split(string(content), "\n")

	var checkMatch func(string) bool
	var highlight func(string) string

	if useRegex {
		re, err := regexp.Compile(searchTerm)
		if err != nil {
			return fmt.Errorf("invalid regular expression %q: %w", searchTerm, err)
		}
		checkMatch = re.MatchString
		highlight = func(line string) string {
			// Highlight all occurrences of the regex match in the line.
			return re.ReplaceAllString(line, au.Red("$0").String())
		}
	} else {
		checkMatch = func(line string) bool {
			return strings.Contains(line, searchTerm)
		}
		highlight = func(line string) string {
			return strings.ReplaceAll(line, searchTerm, au.Red(searchTerm).String())
		}
	}

	// Mode to only list files with matches.
	if filesWithMatches {
		for _, line := range lines {
			if checkMatch(line) {
				fmt.Println(filePath)
				return nil // Found a match, print filename and stop processing this file.
			}
		}
		return nil
	}

	found := false
	for i, line := range lines {
		if checkMatch(line) {
			if !found {
				// Print file header only on the first match in the file
				fmt.Printf("\n---\n%s\n---\n", au.Bold(au.Cyan(filePath)))
				found = true
			}

			// Print context before the match
			start := i - contextLines
			if start < 0 {
				start = 0
			}
			for j := start; j < i; j++ {
				fmt.Printf("%d: %s\n", j+1, lines[j])
			}

			// Print the matching line with highlight
			highlightedLine := highlight(line)
			fmt.Printf("%s: %s\n", au.Bold(fmt.Sprintf("%d", i+1)), highlightedLine)

			// Print context after the match
			end := i + contextLines + 1
			if end > len(lines) {
				end = len(lines)
			}
			for j := i + 1; j < end; j++ {
				fmt.Printf("%d: %s\n", j+1, lines[j])
			}
			fmt.Println() // Add a blank line for readability
		}
	}

	return nil
}
