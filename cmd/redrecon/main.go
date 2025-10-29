package main

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"redrecon/internal/config"
	"redrecon/cmd/redrecon/cmd"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "redrecon",
	Short: "RedRecon is a security orchestration tool",
	Long:  `A fast and flexible security orchestration tool built in Go, named RedRecon.`,
	Run: func(cmd *cobra.Command, args []string) {
		slog.Info("Welcome to RedRecon!")
		// If no command is given, show help.
		if len(args) == 0 {
			cmd.Help()
		}
	},

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// A verificação do sistema operacional foi desativada a pedido do usuário.
		// O código original verificava se o sistema era Parrot ou Kali.
		return nil
	},
}

func isSupportedDistro(content []byte) error {
	var isSupported bool
	lowerContent := strings.ToLower(string(content))

	// Check for ID=kali or ID=parrot, allowing for spaces and quotes.
	// Also check ID_LIKE for Debian-based systems that might be Parrot.
	for _, line := range strings.Split(lowerContent, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if strings.Contains(trimmedLine, "id=kali") || strings.Contains(trimmedLine, "id=parrot") {
			isSupported = true
			break
		}
	}
	if !isSupported {
		msg := "unsupported Linux distribution. Please run on Parrot or Kali Linux"
		slog.Error(msg)
		return fmt.Errorf(msg)
	}
	return nil
}

func checkHostOS() error {
	if runtime.GOOS != "linux" {
		msg := fmt.Sprintf("unsupported operating system: %s. This program is optimized for Parrot or Kali Linux", runtime.GOOS)
		slog.Error(msg)
		return fmt.Errorf(msg)
	}

	content, err := os.ReadFile("/etc/os-release")
	if err != nil {
		slog.Error("could not check Linux distribution", "error", err)
		return err
	}

	return isSupportedDistro(content)
}

func init() {
	cobra.OnInitialize(initConfig)
	cmd.AddCommands(rootCmd)
}

func initConfig() {
	if err := config.LoadConfig(); err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}
}

func main() {
	// This needs to be called before Execute because initConfig is called by cobra.OnInitialize
	initConfig()
	
	// Execute the root command. Cobra will parse the command-line arguments
	// and run the appropriate command's 'Run' function.
	if err := rootCmd.Execute(); err != nil {
		slog.Error("Whoops. There was an error while executing your CLI", "error", err)
		os.Exit(1)
	}
}
