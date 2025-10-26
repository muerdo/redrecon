package cmd

import (
	"fmt"
	"redrecon/pkg/infra"
	"log/slog"

	"github.com/spf13/cobra"
)

var (
	infraTarget    string
	skipInfraSteps []string
)

// InfraCmd represents the infra command
var InfraCmd = &cobra.Command{
	Use:   "infra <target>",
	Short: "Executes an infrastructure scan workflow on a target",
	Long: `The 'infra' command automates a security infrastructure scanning workflow
against a target domain. It focuses on network-level discovery and analysis:

- Subdomain Enumeration (subfinder)
- IP Address Resolution (dnsx)
- Port Scanning (nmap)
- Service Vulnerability Scanning (nuclei)

All results are saved in 'results/<target>/infra'.

Usage Example:
  redrecon infra example.com`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) > 0 {
			infraTarget = args[0]
		}

		if infraTarget == "" {
			slog.Error("Target must be specified either as an argument or with the -t/--target flag")
			return
		}

		summary, err := infra.StartInfraScan(infraTarget, skipInfraSteps, slog.Default())
		if err != nil {
			// Error is logged within the function
		} else {
			fmt.Println(summary)
		}
	},
}

func init() {
	InfraCmd.Flags().StringVarP(&infraTarget, "target", "t", "", "Target domain for infrastructure scan (e.g., example.com)")
	InfraCmd.Flags().StringSliceVarP(&skipInfraSteps, "skip", "s", []string{}, "Skip a specific step in the infra scan (e.g., nmap, nuclei)")
}