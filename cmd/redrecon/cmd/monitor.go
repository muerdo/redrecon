package cmd

import (
	"log/slog"
	"os"
	"time"

	"redrecon/pkg/monitor"
	"redrecon/pkg/target"

	"github.com/spf13/cobra"
)

var (
	monitorTarget  string
	monitorFreqStr string
)

var MonitorCmd = &cobra.Command{
	Use:   "monitor <target | target_file.txt>",
	Short: "Continuously monitor targets for new vulnerabilities",
	Long: `The 'monitor' command runs a continuous security scan against one or more targets,
checking for new vulnerabilities at a specified frequency.

It performs a lightweight discovery and runs Nuclei with a curated set of templates.
If a new vulnerability is found (i.e., one not seen in the previous scan),
a notification is sent to the configured Discord webhook.

Usage Examples:
  # Monitor a single domain every 6 hours (default frequency)
  redrecon monitor example.com

  # Monitor targets from a file every 24 hours
  redrecon monitor targets.txt -f 24h`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			monitorTarget = args[0]
		}

		if monitorTarget == "" {
			slog.Error("A target or target file must be specified for monitoring.")
			return
		}

		frequency, err := time.ParseDuration(monitorFreqStr)
		if err != nil {
			slog.Error("Invalid frequency duration. Use format like '1h', '30m', '12h'.", "error", err)
			return
		}

		var targetsToScan []string
		if target.IsTargetFile(monitorTarget) {
			parsedTargets, err := target.ParseTargetFile(monitorTarget)
			if err != nil {
				slog.Error("Failed to parse target file", "error", err)
				os.Exit(1)
			}
			targetsToScan = parsedTargets
		} else {
			targetsToScan = []string{monitorTarget}
		}

		monitor.Start(targetsToScan, frequency)
	},
}

func init() {
	MonitorCmd.Flags().StringVarP(&monitorTarget, "target", "t", "", "Target domain or file with a list of targets")
	MonitorCmd.Flags().StringVarP(&monitorFreqStr, "frequency", "f", "6h", "Frequency of monitoring scans (e.g., '30m', '1h', '24h')")
}