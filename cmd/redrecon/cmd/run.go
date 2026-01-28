package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"redrecon/pkg/ai"
	"redrecon/pkg/infra"
	"redrecon/pkg/recon"
	"redrecon/pkg/scan"
	"redrecon/pkg/target"
	"redrecon/pkg/utils"
	"redrecon/pkg/web"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

var (
	runReconSkipSteps     []string
	runScanSkipSteps      []string
	runScanOnlySteps      []string
	runIsAggressive       bool
	runSkipAnalysis       bool
	runForceScan          bool
	runWithInfra          bool
	runWithWeb            bool
	runBbotModules        string
	runWebAllowSubdomains bool
	runBbotPresets        string
	runNucleiGroup        string
	runFollowRedirects    bool
	runDownloadContent    bool
	runInputFile          string
	runWithAI             bool
	runProxies            utils.StringSliceFlag
	runProxyFile          string
)

var RunCmd = &cobra.Command{
	Use:   "run [target]",
	Short: "Executa um fluxo de trabalho completo de reconhecimento e varredura em um alvo.",
	Long: `O comando 'run' automatiza todo o processo de avaliação de segurança. Ele inicia com a fase de reconhecimento ('recon') para descobrir e mapear ativos e, se hosts ativos forem encontrados, prossegue para a fase de varredura ('scan').

**Dicas de Uso:**
  - **Scan Rápido:** redrecon run example.com --bbot-modules recon/scans/light --scan-only nuclei
  - **Foco em Web:** redrecon run example.com --recon-skip portscan --scan-skip nikto
  - **Enumeração de Infra:** redrecon run example.com --with-infra --scan-skip all
  - **Análise com IA:** redrecon run example.com --with-ai`,
	Args: func(cmd *cobra.Command, args []string) error {
		if runInputFile == "" && len(args) < 1 {
			return fmt.Errorf("requer um alvo como argumento ou um arquivo de entrada com a flag --input-file")
		}
		if runInputFile != "" && len(args) > 0 {
			return fmt.Errorf("não é possível usar um alvo como argumento e um arquivo de entrada ao mesmo tempo")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		ctx := context.Background()

		targets, err := utils.GetTargets(args, runInputFile)
		if err != nil {
			logger.Error("Falha ao obter alvos", "error", err)
			os.Exit(1)
		}

		var proxyManager *utils.ProxyManager
		var proxies []string

		if len(runProxies) > 0 {
			proxies = runProxies
		} else if runProxyFile != "" {
			loadedProxies, err := utils.ReadLines(runProxyFile)
			if err != nil {
				logger.Error("Falha ao ler o arquivo de proxies da flag, continuando sem eles.", "file", runProxyFile, "error", err)
			} else {
				proxies = loadedProxies
			}
		}
		proxyManager = utils.NewProxyManagerFromList(proxies)

		for _, initialTarget := range targets {
			taskIdentifier := target.GetRootDomain(initialTarget)
			var presets []string
			if runBbotPresets != "" {
				presets = strings.Split(runBbotPresets, ",")
			}
			summary, files, err := ExecuteRunCommandWorkflow(ctx, taskIdentifier, initialTarget, runReconSkipSteps, runScanSkipSteps, runScanOnlySteps, runBbotModules, presets, runNucleiGroup, runIsAggressive, runSkipAnalysis, runFollowRedirects, runForceScan, runDownloadContent, runWithAI, proxyManager, logger)
			if err != nil {
				logger.Error("O fluxo 'run' falhou", "target", initialTarget, "error", err)
				continue // Continua para o próximo alvo
			}
			fmt.Println(summary)
			printFilesInBox(fmt.Sprintf("Arquivos do Run para %s", initialTarget), files)
		}
		logger.Info(" Todos os fluxos para o alvo foram processados.")
	},
}

func ExecuteRunCommandWorkflow(ctx context.Context, taskIdentifier, initialTarget string, reconSkipSteps, scanSkipSteps, scanOnlySteps []string, bbotModules string, bbotPresets []string, nucleiGroup string, isAggressive, skipAnalysis, followRedirects, forceScan, downloadContent, withAI bool, proxyManager *utils.ProxyManager, logger *slog.Logger) (string, []string, error) {
	var wg sync.WaitGroup
	if runWithInfra {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Info(fmt.Sprintf("- Iniciando Varredura de Infraestrutura para `%s` em paralelo...", initialTarget))
			infra.StartInfra(taskIdentifier, initialTarget, []string{}, strings.Join(bbotPresets, ","), proxyManager, logger)
		}()
	}
	if runWithWeb {
		wg.Add(1)
		go func() {
			defer wg.Done()
			webTarget := "https://" + initialTarget
			logger.Info(fmt.Sprintf("- Iniciando Análise Web para `%s` em paralelo...", webTarget))
			web.StartWeb(taskIdentifier, webTarget, 2, runWebAllowSubdomains, "", []string{}, proxyManager, logger)
		}()
	}

	logger.Info(fmt.Sprintf("--- 🎬 INICIANDO FLUXO DE RECONHECIMENTO PARA: %s ---", initialTarget))
	var bbotModulesSlice []string
	if bbotModules != "" {
		bbotModulesSlice = strings.Split(bbotModules, ",")
	}
	reconSummary, reconFiles, liveHostsFound, err := recon.StartRecon(ctx, taskIdentifier, initialTarget, []string{initialTarget}, reconSkipSteps, nil, bbotPresets, bbotModulesSlice, skipAnalysis, followRedirects, true, forceScan, downloadContent, false, "", "", proxyManager, nil, "", "", "", logger, false)
	if err != nil {
		return "", nil, fmt.Errorf("o fluxo 'recon' falhou: %w", err)
	}

	var finalSummary strings.Builder
	finalSummary.WriteString(reconSummary)
	allFiles := reconFiles

	if liveHostsFound || forceScan {
		logger.Info(fmt.Sprintf("--- 🎬 INICIANDO FLUXO DE SCAN PARA: %s ---", taskIdentifier))
		reconTargetsFilePath := filepath.Join("results", utils.SanitizeTargetForPath(taskIdentifier), "recon", "recon_targets.txt")
		scanSummary, scanFiles, err := scan.StartScan(ctx, taskIdentifier, reconTargetsFilePath, scanSkipSteps, scanOnlySteps, nucleiGroup, strings.Join(bbotPresets, ","), "", "", isAggressive, true, proxyManager, "", "", "", logger)
		if err != nil {
			return "", nil, fmt.Errorf("o fluxo 'scan' falhou: %w", err)
		}
		finalSummary.WriteString("\n\n")
		finalSummary.WriteString(scanSummary)
		allFiles = append(allFiles, scanFiles...)
	} else {
		logger.Warn("Nenhum host ativo encontrado. Pulando a fase de Scan.", "target", initialTarget)
	}

	wg.Wait()

	if withAI {
		logger.Info("--- 🤖 INICIANDO ANÁLISE COM IA ---", "target", initialTarget)
		aiAnalysis, err := ai.AnalyzeRunResults(ctx, taskIdentifier, initialTarget, allFiles, logger)
		if err != nil {
			logger.Error("Falha na análise com IA", "error", err)
		} else {
			printAIAnalysisInBox("Análise Holística da IA", aiAnalysis)
		}
	}

	return finalSummary.String(), allFiles, nil
}

func printAIAnalysisInBox(title, analysis string) {
	border := "================================================================================"
	fmt.Println(border)
	fmt.Printf(" %s\n", title)
	fmt.Println(border)
	fmt.Println(analysis)
	fmt.Println(border)
}

func init() {
	RunCmd.Flags().StringSliceVar(&runReconSkipSteps, "recon-skip", []string{}, "Pula etapas do recon (ex: webenum,fuzz).")
	RunCmd.Flags().StringSliceVar(&runScanSkipSteps, "scan-skip", []string{}, "Pula etapas do scan (ex: nikto,nuclei).")
	RunCmd.Flags().StringSliceVar(&runScanOnlySteps, "scan-only", []string{}, "Executa apenas etapas específicas do scan (ex: nuclei).")
	RunCmd.Flags().BoolVar(&runIsAggressive, "aggressive", false, "Usa perfis de varredura mais agressivos.")
	RunCmd.Flags().BoolVar(&runSkipAnalysis, "skip-analysis", false, "Pula a fase de análise e enriquecimento do recon.")
	RunCmd.Flags().BoolVar(&runForceScan, "force-scan", false, "Força a execução do scan mesmo sem hosts ativos encontrados.")
	RunCmd.Flags().BoolVar(&runWithInfra, "with-infra", false, "Executa a varredura de infraestrutura em paralelo.")
	RunCmd.Flags().BoolVar(&runWithWeb, "with-web", false, "Executa a análise web aprofundada em paralelo.")
	RunCmd.Flags().StringVar(&runBbotModules, "bbot-modules", "", "Define módulos específicos do bbot para o recon.")
	RunCmd.Flags().StringVar(&runBbotPresets, "bbot-presets", "", "Define presets do bbot para o recon (ex: web-basic,subdomain-enum).")
	RunCmd.Flags().StringVar(&runNucleiGroup, "nuclei-group", "", "Define um grupo de templates do Nuclei para o scan.")
	RunCmd.Flags().BoolVar(&runFollowRedirects, "follow-redirects", true, "Habilita o rastreamento de redirecionamentos HTTP.")
	RunCmd.Flags().BoolVar(&runDownloadContent, "download-content", false, "Habilita o download de conteúdo JS durante o recon.")
	RunCmd.Flags().StringVarP(&runInputFile, "input-file", "i", "", "Arquivo de entrada contendo a lista de alvos.")
	RunCmd.Flags().BoolVar(&runWithAI, "with-ai", false, "Executa uma análise com IA sobre os resultados consolidados.")
	RunCmd.Flags().Var(&runProxies, "proxies", "Define uma lista de proxies para usar durante a execução (pode ser usado várias vezes).")
	RunCmd.Flags().StringVar(&runProxyFile, "proxy-file", "", "Define um arquivo contendo uma lista de proxies para usar.")
}


func init() {
	RootCmd.AddCommand(RunCmd)
}
