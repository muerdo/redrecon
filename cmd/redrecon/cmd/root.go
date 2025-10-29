package cmd

import (
	"github.com/spf13/cobra"
)

// AddCommands registers all the command handlers to the root command.
func AddCommands(root *cobra.Command) {
	root.AddCommand(ChainCmd)
	root.AddCommand(BotCmd)
	root.AddCommand(InfraCmd)
	root.AddCommand(MonitorCmd)
	root.AddCommand(ReconCmd)
	root.AddCommand(ScanCmd)
	root.AddCommand(SearchCmd)
	root.AddCommand(WebCmd)
}
