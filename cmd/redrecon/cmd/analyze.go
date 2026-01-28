package cmd

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"redrecon/pkg/target"
	"redrecon/pkg/ai"
	"redrecon/pkg/utils"

	"github.com/spf13/cobra"
)

var AnalyzeCmd = &cobra.Command{
	Use:   "analyze [target]",
	Short: "Executa uma análise holística com IA sobre os resultados de um alvo.",
	Long: `O comando 'analyze' consolida os resultados mais importantes das fases de recon, scan e infra para um alvo específico.
Ele formata os dados de forma otimizada (similar ao TOON) e os envia para um modelo de IA para uma análise aprofundada.
A IA irá correlacionar informações, identificar vetores de ataque, sugerir cadeias de exploração e fornecer recomendações estratégicas.

Este comando é ideal para obter uma visão geral e acionável do estado de segurança de um alvo após a conclusão dos scans.
Certifique-se de que sua chave de API de IA esteja configurada em 'config.yaml'.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		targetArg := args[0]
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		ctx := context.Background()
		taskIdentifier := target.GetRootDomain(targetArg)

		resultsPath := filepath.Join("results", taskIdentifier)

		if !utils.DirExistsAndIsNotEmpty(resultsPath) {
			logger.Error("Nenhum diretório de resultados encontrado para o alvo. Execute uma varredura primeiro.", "target", targetArg)
			return
		}

		// 1. Coletar todos os arquivos de resultado do alvo.
		var resultFiles []string
		err := filepath.Walk(resultsPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				resultFiles = append(resultFiles, path)
			}
			return nil
		})
		if err != nil {
			logger.Error("Falha ao varrer o diretório de resultados", "path", resultsPath, "error", err)
			return
		}

		// 2. Chamar a função de análise holística que agora consolida e formata os dados.
		logger.Info("Consolidando e formatando resultados para análise da IA...")
		aiAnalysis, err := ai.AnalyzeRunResults(ctx, taskIdentifier, targetArg, resultFiles, logger)
		if err != nil {
			logger.Error("Falha na análise com IA", "error", err)
		} else {
			// 3. Imprimir o resultado formatado.
			printAIAnalysisInBox("Análise Holística da IA", aiAnalysis)
		}
	},
}


func init() {
	RootCmd.AddCommand(AnalyzeCmd)
}
