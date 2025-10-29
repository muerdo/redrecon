package cmd

import (
	"fmt"
	"log/slog"
	"time"

	"redrecon/pkg/monitor"
	"redrecon/pkg/target"

	"github.com/spf13/cobra"
)

var (
	monitorTarget   string
	monitorFrequency string
)

// MonitorCmd represents the monitor command
var MonitorCmd = &cobra.Command{
	Use:   "monitor <target>",
	Short: "Continuously monitors targets for new vulnerabilities",
	Long: `The 'monitor' command runs scans on a schedule to detect new vulnerabilities
or newly exposed assets for one or more targets.

The target can be a single domain, a file containing a list of targets (txt, json, xml),
or a directory containing multiple result files. The tool will parse and normalize
all inputs to execute the monitoring on each valid target found.

Notifications for new findings are sent via the Discord webhook configured in 'config.yaml'.

Usage Examples:
  # Monitor a single target with the default frequency (6h)
  redrecon monitor example.com

  # Monitor all targets from a file with a 12-hour frequency
  redrecon monitor -f 12h targets.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			monitorTarget = args[0]
		}

		if monitorTarget == "" {
			return fmt.Errorf("a target or target file must be specified for the monitor command")
		}

		frequency, err := time.ParseDuration(monitorFrequency)
		if err != nil {
			return fmt.Errorf("invalid frequency format: %w. Use formats like '1h', '30m', '12h'", err)
		}

		var targetsToScan []string
		if target.IsTargetDirectory(monitorTarget) {
			slog.Info("Target is a directory, parsing for targets...", "path", monitorTarget)
			parsedTargets, err := target.ParseTargetDirectory(monitorTarget)
			if err != nil {
				return fmt.Errorf("failed to parse target directory: %w", err)
			}
			targetsToScan = parsedTargets
		} else if target.IsTargetFile(monitorTarget) {
			slog.Info("Target is a file, parsing for targets...", "path", monitorTarget)
			parsedTargets, err := target.ParseTargetFile(monitorTarget)
			if err != nil {
				return fmt.Errorf("failed to parse target file: %w", err)
			}
			targetsToScan = parsedTargets
		} else {
			targetsToScan = []string{monitorTarget}
		}

		// Agrupa todos os alvos sob seu domínio raiz para evitar monitoramento duplicado.
		rootTargets := make(map[string]struct{})
		for _, t := range targetsToScan {
			rootDomain := target.GetRootDomain(t)
			rootTargets[rootDomain] = struct{}{}
		}

		var uniqueRootTargets []string
		for root := range rootTargets {
			uniqueRootTargets = append(uniqueRootTargets, root)
		}

		// A função Start já é um processo de longa duração, então não precisa de um loop aqui.
		monitor.Start(uniqueRootTargets, frequency)
		return nil
	},
}

func init() {
	MonitorCmd.Flags().StringVarP(&monitorTarget, "target", "t", "", "Target for monitoring (domain, file, or directory). Can also be provided as an argument.")
	MonitorCmd.Flags().StringVarP(&monitorFrequency, "frequency", "f", "6h", "Frequency of the monitoring scans (e.g., '1h', '30m', '12h').")
}