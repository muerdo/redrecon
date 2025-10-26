package cmd

import (
	"log/slog"

	"redrecon/internal/config"
	"redrecon/pkg/discord"
	"redrecon/pkg/infra"
	"redrecon/pkg/monitor"

	"github.com/spf13/cobra"
)

// BotCmd represents the bot command
var BotCmd = &cobra.Command{
	Use:   "bot",
	Short: "Manage the RedRecon Discord bot",
	Long:  `Provides commands to start and manage the RedRecon Discord bot.`,
}

var botStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Starts the Discord bot as a foreground process",
	Long: `Starts the RedRecon Discord bot, which will listen for commands in your
Discord server. This command runs as a long-running process until terminated (e.g., with CTRL+C).

Make sure you have configured your bot token and other settings in config.yaml.`,
	Run: func(cmd *cobra.Command, args []string) {
		if !config.Cfg.Engine.Discord.Enabled || config.Cfg.Engine.Discord.Token == "" {
			slog.Error("Discord bot is not enabled or token is not configured in config.yaml.")
			slog.Info("To start the bot, set 'engine.discord.enabled' to true and provide a valid 'token'.")
			return
		}

		// Wire up command handlers for the Discord bot to break import cycles.
		discord.StartMonitorFunc = monitor.Start
		discord.StartInfraFunc = infra.StartInfraScan

		// This is a blocking call, it will run until the process is terminated.
		discord.StartBot(config.Cfg.Engine.Discord.Token, config.Cfg.Engine.Discord.Prefix)
	},
}

func init() {
	BotCmd.AddCommand(botStartCmd)
}