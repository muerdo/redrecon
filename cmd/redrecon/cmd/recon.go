package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"redrecon/pkg/recon"
	"redrecon/pkg/target"
	"redrecon/pkg/utils"

	"context"

	"github.com/spf13/cobra"
)

var (
	reconTarget          string
	reconSkipSteps       []string
	reconNoRedirects     bool
	reconFollowRedirects bool
	reconSkipAnalysis    bool // Nova flag para pular a Fase 5
	reconForceScan       bool
	reconProxies         utils.StringSliceFlag
	reconProxyFile       string
	reconHeaders         utils.StringSliceFlag
	reconCookies         string
	reconBBotPreset      string
	reconNucleiTags      string
	reconDownloadContent bool
	reconStaticAnalysis  bool
	reconStream          bool // Streaming Mode
)

var ReconCmd = &cobra.Command{
	Use:   "recon <target>",
	Short: "Performs web reconnaissance on a target",
	Long: `The 'recon' command orchestrates a series of tools to perform comprehensive web reconnaissance.
It discovers subdomains, validates live hosts, crawls for URLs, and analyzes JavaScript files for secrets and endpoints.

 **Performance & Memory Tips:**
- **Resource Heavy Tools:** 'bbot' and 'portscan' (Naabu) can be memory and CPU intensive. If running on a VPS with limited resources, consider skipping them using '--skip bbot,portscan'.
- **Concurrency:** Ensure your 'config.yaml' has appropriate 'max_parallel_tasks' settings for your machine.
- **Proxies:** Rotating proxies ('--proxies' or '--proxy-file') is highly recommended to avoid rate limits and 429 errors, which slow down the process.

 **Tool Insights:**
- **Core Tools:** 'subfinder', 'httpx', and 'nuclei' provide the highest value/time ratio.
- **Disabled by Default:** Check 'tools.yaml' for tools like 'bruteforce' or specific heavy scanners that might be disabled to save time.
- **Aggressive Mode:** Using '--bbot-preset kitchen-sink' activates a massive scan. Ensure you have permission and resources!

 **Workflow:**
1. **Discovery:** Uncover, IP Resolution, Passive Enumeration.
2. **Validation:** Httpx probing for live hosts.
3. **Deep Dive:** BBOT (if enabled), Crawler (Katana), and JS Analysis.
4. **Vulnerability:** Basic vulnerability checks and secret scanning.

Usage Examples:
  redrecon recon example.com
  redrecon recon targets.txt --skip bbot --follow-redirects
  redrecon recon example.com --no-redirects`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Create a cancellable context
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

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

		logFile, err := os.OpenFile("redrecon.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return fmt.Errorf("failed to open log file: %w", err)
		}
		defer logFile.Close()
		logger := slog.New(slog.NewTextHandler(logFile, nil))
		fmt.Println("Logs being written to redrecon.log")

		var proxyManager *utils.ProxyManager
		var proxies []string

		// Load proxies using centralized logic
		proxies, err = utils.LoadProxiesFromFlagsOrDefault(logger, reconProxies, reconProxyFile)
		if err != nil {
			logger.Error("Failed to load proxies", "error", err)
		}

		proxyManager = utils.NewProxyManagerFromList(proxies)

		followRedirects := true
		if reconNoRedirects {
			followRedirects = false
		}
		if reconFollowRedirects {
			followRedirects = true
		}

		rootTargets := make(map[string][]string)
		for _, t := range targetsToScan {
			rootDomain := target.GetRootDomain(t)
			rootTargets[rootDomain] = append(rootTargets[rootDomain], t)
		}

		for root, subs := range rootTargets {
			// Check context before starting new target
			if ctx.Err() != nil {
				break
			}

			// If Streaming Mode is enabled
			if reconStream {
				// We need to initialize the state but not run the full synchronous StartRecon.
				// However, StartRecon creates the state internally.
				// We should refactor StartRecon to split state creation or modify StartRecon to accept a config/mode object.
				// For now, let's assume StartRecon handles everything or we call a new StartStreamingRecon if we pass the flag.
				// But StartStreamingRecon takes a *reconState.
				// We need to create the state first.
				// Let's create a Helper to Init State.
				// Or, simpler: Call StartRecon with a special flag/mode?
				// StartRecon signature is huge.
				// Let's verify if we can just re-use StartRecon logic but switch to streaming inside it?
				// No, StartRecon is linear.
				// We should create a new entry point that prepares the state.
				// Since StartRecon does a lot of prep, maybe we can extract `NewReconState`?
				// Since we cannot easily refactor `NewReconState` without changing `recon.go` a lot,
				// let's add `StartStreamingRecon` call here if we can construct state.
				// ...
				// actually, simpler approach:
				// Call StartRecon but add a "stream" argument to it?
				// Let's modify StartRecon signature in `pkg/recon/recon.go` later.
				// For now, let's just error if user tries stream without implementation support in StartRecon.
				// But I just added `StartStreamingRecon(state *reconState)` in `pkg/recon/pipeline.go`.
				// I need to construct `reconState` here.
				// Copying `StartRecon` state initialization logic is risky (duplication).
				// Best way: Modify `StartRecon` to take options struct or add `stream` bool.

				// Let's rely on standard StartRecon for now but add the flag to it.
				// StartRecon definition:
				// func StartRecon(..., stream bool, ...)
			}

			// We will modify StartRecon in `pkg/recon/recon.go` to accept `stream` boolean.
			summary, _, _, err := recon.StartRecon(ctx, root, root, subs, reconSkipSteps, nil, nil, nil, reconSkipAnalysis, followRedirects, true, reconForceScan, reconDownloadContent, reconStaticAnalysis, reconBBotPreset, reconNucleiTags, proxyManager, reconHeaders, reconCookies, "", "", logger, reconStream)
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
	ReconCmd.Flags().BoolVar(&reconFollowRedirects, "follow-redirects", true, "Enable or disable following HTTP redirects during live host validation.")
	ReconCmd.Flags().BoolVar(&reconForceScan, "force-scan", false, "Force scanning even if no live hosts are found, using resolved subdomains.")
	ReconCmd.Flags().Var(&reconProxies, "proxies", "Define uma lista de proxies para usar durante a execução (pode ser usado várias vezes)")
	ReconCmd.Flags().StringVar(&reconProxyFile, "proxy-file", "", "Define um arquivo contendo uma lista de proxies para usar")
	ReconCmd.Flags().Var(&reconHeaders, "headers", "Custom headers to include in requests (e.g. 'Authorization: Bearer token')")
	ReconCmd.Flags().StringVar(&reconCookies, "cookies", "", "Cookies to include in requests (e.g. 'session=123; other=456')")
	ReconCmd.Flags().StringVar(&reconBBotPreset, "bbot-preset", "", "BBot preset to use (e.g. 'passive', 'active', 'aggressive')")
	ReconCmd.Flags().StringVar(&reconNucleiTags, "nuclei-tags", "", "Nuclei tags to use (e.g. 'cves,critical')")
	ReconCmd.Flags().BoolVar(&reconDownloadContent, "download-content", false, "Download full site content (mirror) for static analysis.")
	ReconCmd.Flags().BoolVar(&reconStaticAnalysis, "static-analysis", false, "Run static analysis (semgrep) on downloaded content.")
	ReconCmd.Flags().BoolVar(&reconStream, "stream", false, "Enable Streaming Mode (Pipeline) for faster parallel results.")
}

func init() {
	RootCmd.AddCommand(ReconCmd)
}
