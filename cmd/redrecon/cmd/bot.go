package cmd

import (
	"fmt"
	"log/slog"

	"redrecon/internal/config"
	"redrecon/pkg/discord"

	"github.com/spf13/cobra"
)

var BotCmd = &cobra.Command{
	Use:   "bot [config_path]",
	Short: "Inicia o bot do RedRecon no Discord para comandos interativos",
	Long: `O comando 'bot' inicializa e executa o bot do Discord.
Uma vez em execução, o bot ouvirá por comandos nos canais configurados (ex: !recon, !scan).
Este modo é destinado a sessões interativas e de longa duração e requer que o Discord
esteja habilitado e configurado no seu arquivo 'config.yaml'.

Você pode fornecer um caminho para o arquivo de configuração como um argumento ou usar a flag global -c.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Obter o valor da flag global '-c'
		configFlag, _ := cmd.Flags().GetString("config")

		// Determinar qual caminho de configuração usar
		pathToLoad := ""
		if len(args) > 0 {
			// Prioridade 1: Argumento posicional (ex: ./redrecon bot config.yaml)
			pathToLoad = args[0]
		} else if configFlag != "" {
			// Prioridade 2: Flag global (ex: ./redrecon -c config.yaml bot)
			pathToLoad = configFlag
		}

		// Carregar a configuração
		if err := config.LoadConfig(pathToLoad); err != nil {
			slog.Error("Falha fatal ao carregar a configuração", "error", err)
			return
		}

		if !config.Cfg.Engine.Discord.Enabled {
			slog.Error("O bot do Discord está desabilitado na configuração. Não é possível iniciar o modo bot.")
			fmt.Println("Por favor, habilite o bot no seu arquivo config.yaml para usar este comando.")
			return
		}

		slog.Info("Bot do Discord está habilitado. Iniciando...")
		discord.StartBot() // Assumindo que esta é a função que inicia o bot
	},
}

func init() {
}

func init() {
	RootCmd.AddCommand(BotCmd)
}
