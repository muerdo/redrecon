package cmd

import (
	"log/slog"
	"net/url"
	"os"
	"redrecon/pkg/utils"
	"redrecon/pkg/web"
	"strings"

	"github.com/spf13/cobra"
)

var (
	webTarget    string
	crawlDepth   int
	proxyType    string
	proxies      utils.StringSliceFlag
	webProxyFile string
)

var WebCmd = &cobra.Command{
	Use:   "web <target>",
	Short: "Executes a web application scan workflow on a target",
	Long: `The 'web' command automates a comprehensive web application security workflow.
It focuses on deep discovery of assets, potential vulnerabilities, and sensitive information exposed in client-side code.

 **Features:**
- **Crawling:** Deep crawling to map the application structure.
- **JS Analysis:** Extracts endpoints and secrets from JavaScript files.
- **Tech Detection:** Identifies the technology stack to tailor further attacks.

 **Usage Tips:**
- **Depth:** Use '--depth' to control how deep the crawler goes (default: 2).
- **Proxies:** Essential for avoiding blocks during aggressive crawling.

Example:
  redrecon web https://example.com
  redrecon web https://example.com --depth 3 --skip bbot`,
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

		var proxyManager *utils.ProxyManager

		// Load proxies using centralized logic
		loadedProxies, err := utils.LoadProxiesFromFlagsOrDefault(logger, proxies, webProxyFile)
		if err != nil {
			logger.Error("Failed to load proxies", "error", err)
		}

		if len(loadedProxies) > 0 {
			proxyManager = utils.NewProxyManager(proxyType, loadedProxies)
		}

		skipSteps, _ := cmd.Flags().GetStringSlice("skip")
		_, _, err = web.StartWeb(taskIdentifier, webTarget, crawlDepth, false, "", skipSteps, proxyManager, logger) // Adicionado allowSubdomains e bbotPreset
		if err != nil {
			slog.Error("Web scan failed", "error", err)
		}
	},
}

func init() {
	var skipSteps []string
	WebCmd.Flags().StringVarP(&webTarget, "target", "t", "", "Target URL for web scan (e.g., https://example.com)")
	WebCmd.Flags().IntVarP(&crawlDepth, "depth", "d", 2, "Maximum crawl depth for the web scanner")
	WebCmd.Flags().StringVar(&proxyType, "proxy-type", "http", "Tipo de proxy (http, socks4, socks5)")
	WebCmd.Flags().Var(&proxies, "proxies", "Endereço do proxy (pode ser usado múltiplas vezes)")
	WebCmd.Flags().StringVar(&webProxyFile, "proxy-file", "", "Define um arquivo contendo uma lista de proxies para usar")
	WebCmd.Flags().StringSliceVar(&skipSteps, "skip", []string{}, "Etapas a serem puladas (ex: bbot, trufflehog)")
}

func init() {
	RootCmd.AddCommand(WebCmd)
}
