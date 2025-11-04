package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"redrecon/pkg/infra"
	"redrecon/pkg/target"

	"github.com/spf13/cobra"
)

var (
	infraTarget   string
	infraSkipSteps []string
)

// InfraCmd represents the infra command
var InfraCmd = &cobra.Command{
	Use:   "infra <target>",
	Short: "Performs infrastructure scanning on a target",
	Long:  `The 'infra' command runs tools like nmap to perform infrastructure-level scanning.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) > 0 {
			infraTarget = args[0]
		}

		if infraTarget == "" {
			return fmt.Errorf("a target must be specified for the infra command")
		}

		var targetsToScan []string
		if target.IsTargetFile(infraTarget) {
			parsedTargets, err := target.ParseTargetFile(infraTarget)
			if err != nil {
				return fmt.Errorf("failed to parse target file: %w", err)
			}
			targetsToScan = parsedTargets
		} else {
			targetsToScan = []string{infraTarget}
		}

		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

		for _, t := range targetsToScan {
			taskIdentifier := t
			slog.Info("===== STARTING INFRA SCAN =====", "target", t, "task_identifier", taskIdentifier)
			// Supondo que infra.StartInfra tenha uma assinatura similar a recon.StartRecon
			summary, _, err := infra.StartInfra(taskIdentifier, t, infraSkipSteps, logger)
			if err != nil {
				slog.Error("Infrastructure scan failed", "target", t, "error", err)
				continue
			}
			fmt.Println(summary)
		}
		return nil
	},
}

func init() {
	InfraCmd.Flags().StringVarP(&infraTarget, "target", "t", "", "Target for infrastructure scan (domain, IP, file).")
	InfraCmd.Flags().StringSliceVarP(&infraSkipSteps, "skip", "s", []string{}, "Comma-separated list of infra steps to skip.")
}