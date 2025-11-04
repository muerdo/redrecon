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
	lowerContent := strings.ToLower(string(content))

	// Verifica se o conteúdo contém os identificadores das distribuições suportadas.
	// Isso é mais simples do que iterar por cada linha.
	if !strings.Contains(lowerContent, "id=kali") && !strings.Contains(lowerContent, "id=parrot") {
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
	// A inicialização da configuração agora é tratada pelo Cobra.
	cobra.OnInitialize(initConfig)
}

func initConfig() {
	if err := config.LoadConfig(); err != nil {
		// Usamos fmt.Println aqui porque o logger pode não estar totalmente configurado ainda.
		fmt.Fprintf(os.Stderr, "Erro fatal: falha ao carregar a configuração: %v\n", err)
		os.Exit(1)
	}
}

func main() {
	// A função Execute do pacote cmd agora é o ponto de entrada principal.
	// Ela lida com a inicialização e execução de todos os comandos.
	cmd.Execute()
}
