package cmd

import (
	"redrecon/pkg/web"
	"log/slog"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	webTarget  string
	crawlDepth int
)

// WebCmd represents the web command
var WebCmd = &cobra.Command{
	Use:   "web <target>",
	Short: "Executes a web application scan workflow on a target",
	Long: `The 'web' command automates a security web application scanning workflow
against a target URL. It focuses on discovering assets and potential vulnerabilities.

- Website Content Crawling (JS, Source Maps, CSS, etc.)

All results are saved in 'results/<target>/web'.

Usage Example:
  redrecon web https://example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			webTarget = args[0]
		}

		if webTarget == "" {
			slog.Error("Target must be specified either as an argument or with the -t/--target flag")
			return
		}

		// Automatically add https scheme if it's missing for user convenience.
		if !strings.HasPrefix(webTarget, "http://") && !strings.HasPrefix(webTarget, "https://") {
			webTarget = "https://" + webTarget
			slog.Debug("Scheme missing, prepending https://", "new_target", webTarget)
		}

		slog.Info("Starting web application scan", "target", webTarget)

		// 1. Crawl the website to download assets
		if err := web.CrawlWebsite(webTarget, crawlDepth); err != nil {
			slog.Error("Failed to execute web scan", "error", err)
			return
		}

		// 2. Analyze the downloaded JavaScript files for endpoints
		parsedURL, err := url.Parse(webTarget)
		if err != nil {
			slog.Error("Could not parse target URL for analysis", "error", err)
			return
		}
		resultsDir := filepath.Join("results", parsedURL.Hostname(), "web")

		if _, err := web.AnalyzeJSFiles(resultsDir); err != nil {
			slog.Error("JavaScript analysis failed", "error", err)
		}
	},
}

func init() {
	// Add flags for the web command.
	WebCmd.Flags().StringVarP(&webTarget, "target", "t", "", "Target URL for web scan (e.g., https://example.com)")
	WebCmd.Flags().IntVarP(&crawlDepth, "depth", "d", 2, "Maximum crawl depth for the web scanner")
}