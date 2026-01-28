package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"redrecon/pkg/infra"
	"redrecon/pkg/target"
	"redrecon/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	infraTarget    string
	infraInputFile string
	infraSkipSteps []string
	infraProxies   utils.StringSliceFlag
	infraProxyFile string
)

var InfraCmd = &cobra.Command{
	Use:   "infra <target>",
	Short: "Performs infrastructure scanning on a target",
	Long: `The 'infra' command performs infrastructure-level scanning using tools like Nmap.
It accepts a single target or a list of targets from a file.

 **Tips:**
- **Privileges:** Nmap often requires root privileges for UDP scans or OS detection. Run with 'sudo' if needed.
- **Output:** Results are saved in the 'results/<target>/infra' directory.
- **Efficiency:** The tool uses smart flags to detecting live hosts before full port scanning.

Example:
  redrecon infra 10.10.10.5
  redrecon infra -i ips.txt`,
	Args: func(cmd *cobra.Command, args []string) error {
		if infraInputFile == "" && len(args) < 1 {
			return fmt.Errorf("requires a target argument or an input file with --input-file")
		}
		if infraInputFile != "" && len(args) > 0 {
			return fmt.Errorf("cannot use both a target argument and an input file")
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		targetsToScan, err := utils.GetTargets(args, infraInputFile)
		if err != nil {
			return err
		}

		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

		var proxyManager *utils.ProxyManager
		var proxies []string

		// Load proxies using centralized logic
		proxies, err = utils.LoadProxiesFromFlagsOrDefault(logger, infraProxies, infraProxyFile)
		if err != nil {
			logger.Error("Failed to load proxies", "error", err)
		}
		proxyManager = utils.NewProxyManagerFromList(proxies)

		for _, t := range targetsToScan {
			taskIdentifier := target.GetRootDomain(t)
			slog.Info("===== STARTING INFRA SCAN =====", "target", t, "task_identifier", taskIdentifier)
			summary, _, err := infra.StartInfra(taskIdentifier, t, infraSkipSteps, "", proxyManager, logger)
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
	InfraCmd.Flags().StringVarP(&infraInputFile, "input-file", "i", "", "Arquivo de entrada contendo a lista de alvos.")
	InfraCmd.Flags().StringSliceVarP(&infraSkipSteps, "skip", "s", []string{}, "Comma-separated list of infra steps to skip.")
	InfraCmd.Flags().Var(&infraProxies, "proxies", "Define uma lista de proxies para usar durante a execução (pode ser usado várias vezes).")
	InfraCmd.Flags().StringVar(&infraProxyFile, "proxy-file", "", "Define um arquivo contendo uma lista de proxies para usar.")
}

func init() {
	RootCmd.AddCommand(InfraCmd)
}
