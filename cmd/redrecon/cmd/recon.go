package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"redrecon/pkg/recon"
	"redrecon/pkg/target"

	"github.com/spf13/cobra"
)

var (
	reconTarget string
	skipSteps   []string
)

// reconCmd represents the recon command
var ReconCmd = &cobra.Command{
	Use:   "recon <target>",
	Short: "Executes a full reconnaissance workflow on a target",
	Long: `The 'recon' command automates a security reconnaissance workflow
against a target domain. It orchestrates a sequence of tools to discover
and analyze assets, including:

- Subdomain enumeration (subfinder, shuffledns)
- Active host validation (httpx)
- URL collection (katana, waybackurls)
- JavaScript and Sourcemap analysis
- Vulnerability scanning (Nuclei, Nikto)
- General reconnaissance (BBot)

All results are saved in an organized directory at 'results/<target>/recon'.

Usage Examples:
  # Run a full reconnaissance on a domain
  redrecon recon example.com

  # Use a custom wordlist for subdomain brute-force
  redrecon recon -w /path/to/my_wordlist.txt example.com

  # Skip specific steps (useful for resuming a scan or focusing on certain areas)
  redrecon recon -s jsanalysis -s nikto example.com

Tips for Effective Reconnaissance:
  - API Keys: For best results with 'subfinder', configure your API keys
    in the '~/.config/subfinder/provider-config.yaml' file.
  - Wordlists: The quality of your subdomain wordlist directly impacts the
    brute-force results. Use high-quality lists.
  - Tools: Ensure all external tools (nuclei, nikto, bbot, etc.)
    are installed and available in your system's PATH.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			reconTarget = args[0]
		}

		if reconTarget == "" {
			slog.Error("A target or target file must be specified.")
			return
		}

		var targetsToScan []string

		if target.IsTargetFile(reconTarget) {
			parsedTargets, err := target.ParseTargetFile(reconTarget)
			if err != nil {
				slog.Error("Failed to parse target file", "error", err)
				os.Exit(1)
			}
			targetsToScan = parsedTargets
		} else {
			targetsToScan = []string{reconTarget}
		}

		for _, t := range targetsToScan {
			slog.Info("===== Starting full recon for target =====", "target", t)
			summary, err := recon.StartRecon(t, skipSteps, slog.Default())
			if err != nil {
				slog.Error("Reconnaissance failed for target", "target", t, "error", err)
				// Continue to the next target instead of stopping
			} else {
				fmt.Println(summary) // Print summary to console
			}
			slog.Info("===== Finished full recon for target =====", "target", t)
		}
	},
}

func init() {
	ReconCmd.Flags().StringVarP(&reconTarget, "target", "t", "", "Target domain for reconnaissance (e.g., example.com). Can also be provided as an argument.")
	ReconCmd.Flags().StringSliceVarP(&skipSteps, "skip", "s", []string{}, "Skip a specific step (can be used multiple times). Possible values: subfinder, dnsvalidator, shuffledns, httpx, htmlanalysis, favicon, ffuf, csp, katana, wayback, jsanalysis, vulntests, nuclei, cvesearch, owasp, nikto, bbot")
}
