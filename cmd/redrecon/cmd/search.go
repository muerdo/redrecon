package cmd

import (
	"fmt"
	"log/slog"

	"redrecon/pkg/search"

	"github.com/spf13/cobra"
)

var (
	searchTerm   string
	searchTarget string
	listOnly     bool
	useRegex     bool
)

var SearchCmd = &cobra.Command{
	Use:   "search <term>",
	Short: "Search for a term in result files",
	Long: `The 'search' command looks for a given term across all generated result files.
It supports plain text and regular expression searches, and can be scoped to a specific target.

Usage Examples:
  # Find all occurrences of "password" (case-insensitive)
  redrecon search "password"

  # Find potential API keys using regex, only in results for example.com
  redrecon search -t example.com -r "[a-fA-F0-9]{32}"

  # List only the files containing the term "admin"
  redrecon search -l "admin"`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			searchTerm = args[0]
		}

		if searchTerm == "" {
			slog.Error("A search term must be provided.")
			return
		}

		output, err := search.ExecuteSearch(searchTerm, searchTarget, listOnly, useRegex)
		if err != nil {
			slog.Error("Search failed", "error", err)
			return
		}
		fmt.Println(output)
	},
}

func init() {
	SearchCmd.Flags().StringVarP(&searchTarget, "target", "t", "", "Scope search to a specific target's results")
	SearchCmd.Flags().BoolVarP(&listOnly, "list-only", "l", false, "List only the files containing the term")
	SearchCmd.Flags().BoolVarP(&useRegex, "regex", "r", false, "Treat the search term as a regular expression")
}