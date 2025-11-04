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
	reconTarget       string
	reconSkipSteps    []string
	reconNoRedirects  bool
	reconFollowRedirects bool
	reconSkipAnalysis bool // Nova flag para pular a Fase 5
	reconForceScan    bool // Renomeado para evitar conflito com run.go
)

// ReconCmd represents the recon command
var ReconCmd = &cobra.Command{
	Use:   "recon <target>",
	Short: "Performs web reconnaissance on a target",
	Long: `The 'recon' command orchestrates a series of tools to perform comprehensive
web reconnaissance. It discovers subdomains, validates live hosts, crawls for URLs,
and analyzes JavaScript files for secrets and endpoints.

This command is the first step in a typical assessment workflow.

Usage Examples:
  # Run a full reconnaissance on a single target
  redrecon recon example.com

  # Run recon on a list of targets from a file
  redrecon recon targets.txt

  # Skip the 'ffuf' and 'wayback' steps during reconnaissance
  redrecon recon example.com --skip ffuf,wayback

  # Disable following HTTP redirects during live host validation
  redrecon recon example.com --no-redirects`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			reconTarget = args[0]
		}

		if reconTarget == "" {
			return fmt.Errorf("a target or target file must be specified for the recon command")
		}

		var targetsToScan []string
		if target.IsTargetDirectory(reconTarget) {
			parsedTargets, err := target.ParseTargetDirectory(reconTarget)
			if err != nil {
				return fmt.Errorf("failed to parse target directory: %w", err)
			}
			targetsToScan = parsedTargets
		} else if target.IsTargetFile(reconTarget) {
			parsedTargets, err := target.ParseTargetFile(reconTarget)
			if err != nil {
				return fmt.Errorf("failed to parse target file: %w", err)
			}
			targetsToScan = parsedTargets
		} else {
			targetsToScan = []string{reconTarget}
		}

		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		
		// A flag --follow-redirects tem precedência sobre --no-redirects
		followRedirects := true
		if reconNoRedirects {
			followRedirects = false
		}
		if reconFollowRedirects {
			followRedirects = true
		}

		// Comportamento unificado: processa cada alvo ou grupo de domínio raiz separadamente.
		rootTargets := make(map[string][]string)
		for _, t := range targetsToScan {
			rootDomain := target.GetRootDomain(t)
			rootTargets[rootDomain] = append(rootTargets[rootDomain], t)
		}

		for root, subs := range rootTargets {
			summary, _, _, err := recon.StartRecon(root, root, subs, reconSkipSteps, reconSkipAnalysis, followRedirects, true, reconForceScan, logger) // true para interativo
			if err != nil {
				slog.Error("Reconnaissance failed for root target", "target", root, "error", err)
				continue
			}
			fmt.Println(summary)
		}

		return nil
	},
}

func init() {
	ReconCmd.Flags().StringVarP(&reconTarget, "target", "t", "", "Target for reconnaissance (domain, file, or directory).")
	ReconCmd.Flags().StringSliceVarP(&reconSkipSteps, "skip", "s", []string{}, "Comma-separated list of recon steps to skip (e.g., 'ffuf,wayback').")
	ReconCmd.Flags().BoolVar(&reconNoRedirects, "no-redirects", false, "Disable following HTTP redirects (deprecated, use --follow-redirects=false).")
	ReconCmd.Flags().BoolVar(&reconSkipAnalysis, "skip-analysis", false, "Skip the entire analysis, enrichment, and detection phase (Phase 5).")
	ReconCmd.Flags().BoolVar(&reconFollowRedirects, "follow-redirects", true, "Enable or disable following HTTP redirects during live host validation.") // Corrected comment
	ReconCmd.Flags().BoolVar(&reconForceScan, "force-scan", false, "Force scanning even if no live hosts are found, using resolved subdomains.") // Renamed
}