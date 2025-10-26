package cmd

import (
	"log/slog"
	
	"redrecon/pkg/scan"

	"github.com/spf13/cobra"
)

var (
	scanTarget   string
	scanTemplate string
)

var ScanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Run vulnerability scans on a target",
	Long: `Executes vulnerability scans using tools like Nuclei against a given target.
You can specify a single target with -t or provide a file with a list of targets.`,
	Run: func(cmd *cobra.Command, args []string) {
		if scanTarget == "" {
			slog.Error("Target must be specified with -t or --target flag")
			return
		}
		if len(args) > 0 {
			scanTarget = args[0]
		}
		scan.StartScan(scanTarget, scanTemplate)
	},
}

func init() {
	ScanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "Target URL or file with a list of targets for scanning")
	ScanCmd.Flags().StringVarP(&scanTemplate, "template", "T", "default", "Nuclei template or directory to use (e.g., 'cves', 'technologies/wordpress.yaml')")
}
