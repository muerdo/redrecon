package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/pkg/adexplorer"
	"redrecon/pkg/types"

	"github.com/spf13/cobra"
)

var (
	adRecon       bool
	adPrivesc     bool
	adLateral     bool
	adDomain      string
	adTargets     []string
	adUsername    string
	adPassword    string
	adHash        string
	adTaskName    string
	adInteractive bool
)

var ADExplorerCmd = &cobra.Command{
	Use:   "ad-explorer",
	Short: "Run a focused reconnaissance and attack workflow against an Active Directory environment.",
	Long: `The 'ad-explorer' command initiates an enumeration and analysis workflow against an Active Directory environment.
It leverages industrial-standard tools like BloodHound, CrackMapExec, and Impacket to map the network.

 **Usage Modes:**
- **Automated:** Runs a standard sequence (SMB, MSSQL, BloodHound, Roasting, Certipy).
- **Interactive:** Use '--interactive' to launch a menu-driven session where you can pick specific attacks (LDAP Dump, SecretsDump, RDP check, etc.).

💡 **Tips:**
- **Creds:** Provide as many credentials as possible (User/Pass or Hash). Automation relies on them.
- **Targets:** List Domain Controllers and other key servers.
- **OpSec:** This is noisy! For stealth, use the interactive mode and pick specific low-noise actions.

Example:
  redrecon ad-explorer -d mycorp.local -t 10.10.10.5 -u svc-user -p 'Password123!'
  redrecon ad-explorer -d mycorp.local -t 10.10.10.5 -u admin -H 'aad3b435b51404eeaad3b435b51404ee:...' --interactive`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		logger := slog.Default()

		taskIdentifier := adTaskName
		if taskIdentifier == "" {
			taskIdentifier = adDomain
		}

		creds := types.Credentials{
			Username: adUsername,
			Password: adPassword,
			Hash:     adHash,
			Domain:   adDomain,
		}

		logger.Info("Initiating AD Explorer", "domain", adDomain, "targets", strings.Join(adTargets, ","))

		if adInteractive {
			return adexplorer.StartInteractiveADRecon(ctx, taskIdentifier, adDomain, adTargets, creds, logger)
		}

		if len(adTargets) == 0 {
			return fmt.Errorf("targets are required for automated mode (use --targets)")
		}

		return adexplorer.StartADRecon(ctx, taskIdentifier, adDomain, adTargets, creds, logger)
	},
}

func init() {
	ADExplorerCmd.Flags().StringVarP(&adDomain, "domain", "d", "", "Target Active Directory domain (e.g., corp.local)")
	ADExplorerCmd.Flags().StringSliceVarP(&adTargets, "targets", "t", []string{}, "List of target IPs or hostnames (e.g., DC IPs)")
	ADExplorerCmd.Flags().StringVarP(&adUsername, "user", "u", "", "Username for authentication")
	ADExplorerCmd.Flags().StringVarP(&adPassword, "password", "p", "", "Password for authentication")
	ADExplorerCmd.Flags().StringVarP(&adHash, "hash", "H", "", "NTLM hash for Pass-the-Hash authentication")
	ADExplorerCmd.Flags().StringVar(&adTaskName, "task-name", "", "Custom name for the task/results directory (defaults to domain)")
	ADExplorerCmd.Flags().BoolVarP(&adInteractive, "interactive", "i", false, "Start in interactive mode with a menu of tools")

	ADExplorerCmd.MarkFlagRequired("domain")
}


func init() {
	RootCmd.AddCommand(ADExplorerCmd)
}
