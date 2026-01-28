package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"redrecon/pkg/scan"
	"redrecon/pkg/target"
	"redrecon/pkg/utils"

	"github.com/spf13/cobra"
)

var (
	scanInputFile    string
	scanSkipSteps    []string
	scanOnlySteps    []string
	scanIsAggressive bool
	scanNucleiGroup  string
	scanBbotPreset   string
	scanTargets      []string
	scanProxies      utils.StringSliceFlag
	scanProxyFile    string
)

var ScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Executa uma varredura de vulnerabilidades a partir de um arquivo de alvos.",
	Long: `The 'scan' command executes vulnerability scanning on a list of targets.
This command is ideal for scanning a pre-defined list of hosts or URLs, bypassing the initial reconnaissance phase.

 **Performance & Memory Tips:**
- **Target Selection:** Use filters like '--only nuclei' if you only care about specific vulnerability classes. This significantly reduces runtime.
- **Nuclei Groups:** The '--nuclei-group' flag is powerful! Use it to target specific tech stacks (e.g., 'wordpress', 'api', 'cves') instead of running all templates.
- **Aggressive Mode:** The '--aggressive' flag enables heavier scans and more presets. Use with caution on production systems.

 **Tool Insights:**
- **Vulnerability Checks:** 'nuclei' and 'dalfox' (XSS) are your primary tools here.
- **Port Scanning:** 'naabu' runs if not skipped. If you already know the open ports or targets are web-only, use '--skip naabu'.
- **Fuzzing:** 'feroxbuster' and 'ffuf' are excellent but can be loud. Ensure you have authorization.

ex:
  # Scan for standard vulnerabilities
  redrecon scan -i targets.txt

  # Focused WordPress scan on live hosts
  redrecon scan -i live_hosts.txt --only nuclei --nuclei-group wordpress

  # Full aggressive scan with BBOT 'kitchen-sink' preset
  redrecon scan -i targets.txt --aggressive --bbot-preset kitchen-sink`,
	Run: func(cmd *cobra.Command, args []string) {
		logFile, err := os.OpenFile("redrecon.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			fmt.Printf("Failed to open log file: %v\n", err)
			os.Exit(1)
		}
		defer logFile.Close()
		logger := slog.New(slog.NewTextHandler(logFile, nil))
		fmt.Println("Logs being written to redrecon.log")
		ctx := context.Background()

		// Combina alvos de argumentos e do arquivo de entrada
		allTargets := append(scanTargets, args...)
		if scanInputFile != "" {
			fileTargets, err := utils.ReadLines(scanInputFile)
			if err != nil {
				logger.Error("Falha ao ler o arquivo de entrada", "file", scanInputFile, "error", err)
				os.Exit(1)
			}
			allTargets = append(allTargets, fileTargets...)
		}

		if len(allTargets) == 0 {
			logger.Error("Nenhum alvo fornecido. Use a flag -i ou forneça alvos como argumentos.")
			os.Exit(1)
		}

		var proxyManager *utils.ProxyManager
		var proxies []string

		// Load proxies using centralized logic
		proxies, err = utils.LoadProxiesFromFlagsOrDefault(logger, scanProxies, scanProxyFile)
		if err != nil {
			logger.Error("Failed to load proxies", "error", err)
		}
		proxyManager = utils.NewProxyManagerFromList(proxies)

		uniqueTargets := utils.UniqueStrings(allTargets)
		logger.Info("Iniciando varredura para alvos", "count", len(uniqueTargets))

		for _, t := range uniqueTargets {
			taskIdentifier := target.GetRootDomain(t)
			logger.Info("Processando alvo", "target", t, "task", taskIdentifier)
			summary, files, err := scan.StartScan(ctx, taskIdentifier, t, scanSkipSteps, scanOnlySteps, scanNucleiGroup, scanBbotPreset, "", "", scanIsAggressive, true, proxyManager, "", "", "", logger)
			if err != nil {
				logger.Error("O fluxo 'scan' falhou para o alvo", "target", t, "error", err)
				continue // Continua para o próximo alvo
			}
			fmt.Println(summary)
			printFilesInBox(fmt.Sprintf("Arquivos do Scan para %s", t), files)
		}
		logger.Info(" Fluxo de scan concluído.")
	},
}

func init() {
	ScanCmd.Flags().StringVarP(&scanInputFile, "input-file", "i", "", "Arquivo de entrada contendo a lista de alvos para o scan (obrigatório).")
	ScanCmd.Flags().StringSliceVar(&scanSkipSteps, "skip", []string{}, "Pula etapas específicas na fase de varredura (ex: --skip nikto,bbot).")
	ScanCmd.Flags().StringSliceVar(&scanOnlySteps, "only", []string{}, "Executa apenas etapas específicas na fase de varredura (ex: --only nuclei,cvesearch).")
	ScanCmd.Flags().BoolVar(&scanIsAggressive, "aggressive", false, "Usa perfis de varredura mais agressivos (ex: preset 'kitchen-sink' do bbot).")
	ScanCmd.Flags().StringVar(&scanNucleiGroup, "nuclei-group", "", "Grupo de templates Nuclei para a fase de scan (ex: wordpress,api).")
	ScanCmd.Flags().StringVar(&scanBbotPreset, "bbot-preset", "", "Define um preset do bbot para o scan (ex: web-basic, kitchen-sink).")
	ScanCmd.Flags().StringSliceVar(&scanTargets, "targets", []string{}, "Lista de alvos para escanear, separados por vírgula.")
	ScanCmd.Flags().Var(&scanProxies, "proxies", "Define uma lista de proxies para usar durante a execução (pode ser usado várias vezes).")
	ScanCmd.Flags().StringVar(&scanProxyFile, "proxy-file", "", "Define um arquivo contendo uma lista de proxies para usar.")

	// Adiciona um alias para a flag de alvos
	ScanCmd.Flags().SetAnnotation("targets", "aliases", []string{"t"})
}

func init() {
	RootCmd.AddCommand(ScanCmd)
}
