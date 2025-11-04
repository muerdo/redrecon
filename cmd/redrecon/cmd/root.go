package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// RootCmd representa o comando base quando chamado sem subcomandos
var RootCmd = &cobra.Command{
	Use:   "redrecon",
	Short: "RedRecon é um orquestrador de reconhecimento e varredura de segurança.",
	Long: `Uma ferramenta de automação construída em Go para agilizar os fluxos de trabalho de segurança,
orquestrando uma suíte de ferramentas populares de código aberto.`,
}

// Execute adiciona todos os comandos filhos ao comando raiz e define as flags apropriadamente.
// Esta é a função principal chamada por main.main().
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	// Adiciona os comandos principais ao comando raiz.
	RootCmd.AddCommand(RunCmd)
	RootCmd.AddCommand(ReconCmd)
	RootCmd.AddCommand(ScanCmd)
	RootCmd.AddCommand(InfraCmd)
	RootCmd.AddCommand(WebCmd)
	RootCmd.AddCommand(ApiCmd) // Adiciona o novo comando de API
	RootCmd.AddCommand(SearchCmd)
	RootCmd.AddCommand(AnalyzeCmd)
	RootCmd.AddCommand(CheckCmd)
	RootCmd.AddCommand(MonitorCmd)
	RootCmd.AddCommand(BotCmd)
}
