package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"redrecon/pkg/api"
	"redrecon/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	apiSkipSteps []string
	apiInputFile string
)

var ApiCmd = &cobra.Command{
	Use:   "api <task_name>",
	Short: "Executa uma varredura de vulnerabilidades focada em APIs.",
	Long:  `O comando 'api' utiliza os resultados das fases de 'recon' e 'infra' para descobrir e testar endpoints de API em busca de vulnerabilidades comuns, como autenticação falha, exposição de dados e problemas de controle de acesso.`,
	Args: func(cmd *cobra.Command, args []string) error {
		if apiInputFile == "" && len(args) < 1 {
			return fmt.Errorf("requer um nome de tarefa como argumento ou um arquivo de entrada com a flag --input-file")
		}
		if apiInputFile != "" && len(args) > 0 {
			return fmt.Errorf("não é possível usar um nome de tarefa como argumento e um arquivo de entrada ao mesmo tempo")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

		tasks, err := utils.GetTargets(args, apiInputFile)
		if err != nil {
			logger.Error("Falha ao obter tarefas", "error", err)
			os.Exit(1)
		}

		var proxyManager *utils.ProxyManager
		var proxies []string

		// Load proxies using centralized logic
		proxies, err = utils.LoadProxiesFromFlagsOrDefault(logger, reconProxies, reconProxyFile)
		if err != nil {
			logger.Error("Failed to load proxies", "error", err)
		}

		proxyManager = utils.NewProxyManagerFromList(proxies)

		for _, taskIdentifier := range tasks {
			logger.Info(fmt.Sprintf("Iniciando varredura de API para a tarefa: %s", taskIdentifier))
			summary, _, err := api.StartAPI(taskIdentifier, apiSkipSteps, "", proxyManager, logger)
			if err != nil {
				logger.Error("Falha no fluxo de varredura de API", "task", taskIdentifier, "error", err)
				continue // Continua para a próxima tarefa
			}
			fmt.Println(summary)
		}
	},
}

func init() {
	ApiCmd.Flags().StringVarP(&apiInputFile, "input-file", "i", "", "Arquivo de entrada contendo a lista de nomes de tarefas.")
	ApiCmd.Flags().StringSliceVarP(&apiSkipSteps, "skip", "s", []string{}, "Pula etapas específicas na varredura de API (ex: 'apifuzz').")
	ApiCmd.Flags().Var(&reconProxies, "proxies", "Define uma lista de proxies para usar durante a execução (pode ser usado várias vezes)")
	ApiCmd.Flags().StringVar(&reconProxyFile, "proxy-file", "", "Define um arquivo contendo uma lista de proxies para usar")
}

func init() {
	RootCmd.AddCommand(ApiCmd)
}
