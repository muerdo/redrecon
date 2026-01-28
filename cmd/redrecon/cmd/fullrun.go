package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"redrecon/pkg/api"
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
	fullrunReconSkipSteps     []string
	fullrunScanSkipSteps      []string
	fullrunScanOnlySteps      []string
	fullrunInfraSkipSteps     []string
	fullrunApiSkipSteps       []string
	fullrunIsAggressive       bool
	fullrunSkipAnalysis       bool
	fullrunForceScan          bool
	fullrunWebDepth           int
	fullrunWebAllowSubdomains bool
	fullrunBbotModules        string
	fullrunNucleiGroup        string
	fullrunBbotPresets        string // Nova flag
	fullrunFollowRedirects    bool
	fullrunDownloadContent    bool
	fullrunInputFile          string
	fullrunProxies            utils.StringSliceFlag
	fullrunProxyFile          string
	fullrunConcurrency        int
)

var FullRunCmd = &cobra.Command{
	Use:   "fullrun [target]",
	Short: "Executa um fluxo COMPLETO e PARALELO (recon, scan, infra, web, api) em um alvo.",
	Long: `O comando 'fullrun' é o mais abrangente, orquestrando a execução simultânea de múltiplos módulos para uma avaliação completa e eficiente.

- **Recon & Scan**: Inicia o fluxo padrão do comando 'run' para descoberta de ativos e varredura de vulnerabilidades.
- **Infra**: Executa a análise de infraestrutura em nuvem e serviços relacionados.
- **Web**: Realiza um crawling aprofundado e análise de conteúdo no alvo web principal.
- **API**: Realiza uma varredura focada em endpoints de API.

**Dicas de Uso:**
  - **Avaliação Rápida:** redrecon fullrun example.com --bbot-modules recon/scans/light --scan-only nuclei --infra-skip nmap
  - **Foco Externo (sem scan de portas):** redrecon fullrun example.com --recon-skip portscan --infra-skip nmap
  - **Máximo Detalhe:** redrecon fullrun example.com --aggressive --web-depth 3`,
	Args: func(cmd *cobra.Command, args []string) error {
		if fullrunInputFile == "" && len(args) < 1 {
			return fmt.Errorf("requer um alvo como argumento ou um arquivo de entrada com a flag --input-file")
		}
		if fullrunInputFile != "" && len(args) > 0 {
			return fmt.Errorf("não é possível usar um alvo como argumento e um arquivo de entrada ao mesmo tempo")
		}
		return nil
	},
	Run: func(cmd *cobra.Command, args []string) {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

		targets, err := utils.GetTargets(args, fullrunInputFile)
		if err != nil {
			logger.Error("Falha ao obter alvos", "error", err)
			os.Exit(1)
		}

		var wg sync.WaitGroup
		// Limita o número de execuções paralelas para não sobrecarregar o sistema.
		// O valor pode ser ajustado ou vir de uma configuração.
		if fullrunConcurrency <= 0 {
			logger.Warn("Valor de concorrência inválido, usando padrão de 4.", "concurrency", fullrunConcurrency)
			fullrunConcurrency = 4
		}
		semaphore := make(chan struct{}, fullrunConcurrency)

		for _, target := range targets {
			wg.Add(1)
			go executeFullRunForTarget(target, logger, &wg, semaphore)
		}

		wg.Wait()
		logger.Info(" Todos os fluxos 'fullrun' foram concluídos para todos os alvos.")
	},
}

// executeFullRunForTarget executa o fluxo de trabalho completo para um único alvo.
func executeFullRunForTarget(initialTarget string, logger *slog.Logger, wg *sync.WaitGroup, semaphore chan struct{}) {
	defer wg.Done()
	semaphore <- struct{}{}        // Adquire um slot
	defer func() { <-semaphore }() // Libera o slot ao final

	var proxyManager *utils.ProxyManager
	var proxies []string

	// Load proxies using centralized logic
	var err error
	proxies, err = utils.LoadProxiesFromFlagsOrDefault(logger, fullrunProxies, fullrunProxyFile)
	if err != nil {
		logger.Error("Failed to load proxies", "error", err)
	}

	proxyManager = utils.NewProxyManagerFromList(proxies)

	{
		ctx := context.Background()

		taskIdentifier := target.GetRootDomain(initialTarget)
		logger.Info(fmt.Sprintf(" Iniciando fluxo COMPLETO e PARALELO para o alvo: %s (Task ID: %s)", initialTarget, taskIdentifier))

		var wg sync.WaitGroup
		wg.Add(4)

		// Goroutine para Recon
		go func() {
			defer wg.Done()
			logger.Info(fmt.Sprintf("- Iniciando Recon para `%s`...", initialTarget))
			var presets []string
			if fullrunBbotPresets != "" {
				presets = strings.Split(fullrunBbotPresets, ",")
			}
			reconSummary, reconFiles, liveHostsFound, err := recon.StartRecon(ctx, taskIdentifier, initialTarget, []string{initialTarget}, fullrunReconSkipSteps, nil, presets, strings.Split(fullrunBbotModules, ","), fullrunSkipAnalysis, fullrunFollowRedirects, true, fullrunForceScan, fullrunDownloadContent, false, "", "", proxyManager, nil, "", "", "", logger, false)
			if err != nil {
				logger.Error("O fluxo 'recon' falhou", "target", initialTarget, "error", err)
				return
			}
			fmt.Println("\n--- Resumo do Recon ---")
			fmt.Println(reconSummary)
			printFilesInBox("Arquivos do Recon", reconFiles)

			// Inicia o Scan se houver hosts ativos
			if liveHostsFound || fullrunForceScan {
				logger.Info(fmt.Sprintf("- Iniciando Scan para `%s`...", taskIdentifier))
				reconTargetsFilePath := filepath.Join("results", utils.SanitizeTargetForPath(taskIdentifier), "recon", "recon_targets.txt")
				scanSummary, scanFiles, err := scan.StartScan(ctx, taskIdentifier, reconTargetsFilePath, fullrunScanSkipSteps, fullrunScanOnlySteps, fullrunNucleiGroup, fullrunBbotPresets, "", "", fullrunIsAggressive, true, proxyManager, "", "", "", logger)
				if err != nil {
					logger.Error("O fluxo 'scan' falhou", "target", taskIdentifier, "error", err)
				} else {
					fmt.Println("\n--- Resumo do Scan ---")
					fmt.Println(scanSummary)
					printFilesInBox("Arquivos do Scan", scanFiles)
				}
			} else {
				logger.Warn("Nenhum host ativo encontrado. Pulando a fase de Scan.", "target", taskIdentifier)
			}
		}()

		// Goroutine para o fluxo de Infra
		go func() {
			defer wg.Done()
			logger.Info(fmt.Sprintf("- Iniciando Varredura de Infraestrutura para `%s`...", initialTarget))
			summary, files, err := infra.StartInfra(taskIdentifier, initialTarget, fullrunInfraSkipSteps, fullrunBbotPresets, proxyManager, logger)
			if err != nil {
				logger.Error("A varredura de infraestrutura falhou", "target", initialTarget, "error", err)
			} else {
				fmt.Println("\n--- Resumo da Varredura de Infraestrutura ---")
				fmt.Println(summary)
				printFilesInBox("Arquivos de Infra", files)
			}
		}()

		// Goroutine para o fluxo de Web
		go func() {
			defer wg.Done()
			webTarget := "https://" + initialTarget
			logger.Info(fmt.Sprintf("- Iniciando Análise Web para `%s` (profundidade: %d)...", webTarget, fullrunWebDepth))
			summary, files, err := web.StartWeb(taskIdentifier, webTarget, fullrunWebDepth, fullrunWebAllowSubdomains, "", []string{}, proxyManager, logger)
			if err != nil {
				logger.Error("A análise web falhou", "target", webTarget, "error", err)
			} else {
				fmt.Println("\n--- Resumo da Análise Web ---")
				fmt.Println(summary)
				printFilesInBox("Arquivos da Web", files)
			}
		}()

		// Goroutine para o fluxo de API
		go func() {
			defer wg.Done()
			logger.Info(fmt.Sprintf("- Iniciando Varredura de API para `%s`...", taskIdentifier))
			summary, files, err := api.StartAPI(taskIdentifier, fullrunApiSkipSteps, fullrunBbotPresets, proxyManager, logger)
			if err != nil {
				logger.Error("A varredura de API falhou", "target", taskIdentifier, "error", err)
			} else {
				fmt.Println("\n--- Resumo da Varredura de API ---")
				fmt.Println(summary)
				printFilesInBox("Arquivos de API", files)
			}
		}()

		wg.Wait()
		logger.Info(fmt.Sprintf(" Fluxo 'fullrun' concluído para o alvo: %s", initialTarget))
	}
}

func printFilesInBox(title string, files []string) {
	if len(files) == 0 {
		return
	}
	fmt.Printf("\n--- %s ---\n", title)
	for _, f := range files {
		fmt.Printf("- %s\n", f)
	}
	fmt.Println(strings.Repeat("-", len(title)+6))
}

func init() {
	RootCmd.AddCommand(FullRunCmd)
}
