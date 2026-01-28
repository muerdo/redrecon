package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/pkg/tools"
	"redrecon/pkg/types"

	"github.com/spf13/cobra"
)

var (
	adAttackDomain   string
	adAttackHost     string
	adAttackUsername string
	adAttackPassword string
	adAttackHash     string
)

var ADAttackCmd = &cobra.Command{
	Use:   "ad-attack",
	Short: "Perform specific attack actions against an Active Directory environment.",
	Long:  `The ad-attack command provides subcommands to execute targeted attacks.`,
}

var bloodyADCmd = &cobra.Command{
	Use:   "bloodyad [bloodyad_args...]",
	Short: "Execute a command using the BloodyAD tool.",
	Long: `This command acts as a wrapper around BloodyAD, allowing you to execute arbitrary commands
while handling authentication parameters through flags.

Example (Add SPN for Kerberoasting):
  redrecon ad-attack bloodyad -d mycorp.local -t 10.10.10.5 -u attacker -p 'Pass123!' -- add spn service-user "HTTP/web.mycorp.local"`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			return fmt.Errorf("you must provide the BloodyAD command and its arguments")
		}

		ctx := context.Background()
		logger := slog.Default()

		creds := types.Credentials{
			Username: adAttackUsername,
			Password: adAttackPassword,
			Hash:     adAttackHash,
			Domain:   adAttackDomain,
		}

		logger.Info("Executing BloodyAD command", "domain", adAttackDomain, "host", adAttackHost, "args", strings.Join(args, " "))
		return tools.RunBloodyAD(ctx, adAttackDomain, adAttackHost, creds, logger, args...)
	},
}

func init() {
	bloodyADCmd.Flags().StringVarP(&adAttackDomain, "domain", "d", "", "Target Active Directory domain")
	bloodyADCmd.Flags().StringVarP(&adAttackHost, "host", "t", "", "Target host (Domain Controller IP)")
	bloodyADCmd.Flags().StringVarP(&adAttackUsername, "user", "u", "", "Username for authentication")
	bloodyADCmd.Flags().StringVarP(&adAttackPassword, "password", "p", "", "Password for authentication")
	bloodyADCmd.Flags().StringVarP(&adAttackHash, "hash", "H", "", "NTLM hash for Pass-the-Hash authentication")

	ADAttackCmd.AddCommand(bloodyADCmd)
}

func init() {
	RootCmd.AddCommand(ADAttackCmd)
}
