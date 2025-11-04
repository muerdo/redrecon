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

var WebCmd = &cobra.Command{
	Use:   "web <target>",
	Short: "Executes a web application scan workflow on a target",
	Long: `The 'web' command automates a security web application scanning workflow against a target URL. It focuses on discovering assets and potential vulnerabilities.
Website Content Crawling (JS, Source Maps, CSS, etc.)
All results are saved in 'results/<target>/web'.
Usage Example: redrecon web https://example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			webTarget = args[0]
		}

		if webTarget == "" {
			slog.Error("Target must be specified either as an argument or with the -t/--target flag")
			return
		}

		if !strings.HasPrefix(webTarget, "http://") && !strings.HasPrefix(webTarget, "https://") {
			webTarget = "https://" + webTarget
			slog.Debug("Scheme missing, prepending https://", "new_target", webTarget)
		}

		slog.Info("Starting web application scan", "target", webTarget)

		parsedURL, err := url.Parse(webTarget)
		if err != nil {
			slog.Error("Could not parse target URL", "error", err)
			return
		}
		taskIdentifier := parsedURL.Hostname()

		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		_, _, err = web.StartWeb(taskIdentifier, webTarget, crawlDepth, logger)
		if err != nil {
			slog.Error("Web scan failed", "error", err)
		}
	},
}

func init() {
	WebCmd.Flags().StringVarP(&webTarget, "target", "t", "", "Target URL for web scan (e.g., https://example.com)")
	WebCmd.Flags().IntVarP(&crawlDepth, "depth", "d", 2, "Maximum crawl depth for the web scanner")
}