package cmd

import (
	"log/slog"
	"os"
	"redrecon/internal/config"
	"redrecon/pkg/utils"

	"github.com/spf13/cobra"
)

var configPath string
var (
	authCookies  string
	authUsername string
	authPassword string
	ctfMode      bool
)

var RootCmd = &cobra.Command{
	Use:   "redrecon",
	Short: "RedRecon é um orquestrador de reconhecimento e varredura de segurança.",
	Long:  `Uma ferramenta de automação construída em Go para agilizar os fluxos de trabalho de segurança, orquestrando uma suíte de ferramentas populares de código aberto.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if err := config.LoadConfig(configPath); err != nil {
			slog.Error("Falha fatal ao carregar a configuração", "error", err)
			os.Exit(1)
		}

		// Initialize Resource Governor
		// Defaults: 60% CPU, 60% RAM, 5s interval
		cpuLimit := config.Cfg.Engine.ResourceLimits.CPUThreshold
		ramLimit := config.Cfg.Engine.ResourceLimits.RAMThreshold
		if cpuLimit == 0 {
			cpuLimit = 60
		}
		if ramLimit == 0 {
			ramLimit = 60
		}

		checkInterval := config.Cfg.Engine.ResourceLimits.CheckInterval
		if checkInterval == "" {
			checkInterval = "5s"
		}

		if err := utils.InitResourceGovernor(cpuLimit, ramLimit, checkInterval, slog.Default()); err != nil {
			slog.Warn("Failed to initialize resource governor", "error", err)
		}

		// Proxies are now optional and will be loaded if available by specific commands (e.g. recon)
		// We no longer block startup waiting for them.

		// Apply CTF optimizations if flag is set
		if ctfMode {
			slog.Info(" CTF mode enabled: fast scan, low footprint, optimized for challenges")
			// Import recon package for ApplyCTFOptimizations
			// This will be called from recon command instead
		}
	},
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().StringVarP(&configPath, "config", "c", "", "Caminho para o arquivo de configuração (ex: /etc/redrecon/config.yaml)")
	RootCmd.PersistentFlags().StringVar(&authCookies, "cookies", "", "Cookies para autenticação (ex: 'JSESSIONID=123; other=456')")
	RootCmd.PersistentFlags().StringVar(&authUsername, "username", "", "Nome de usuário para autenticação básica")
	RootCmd.PersistentFlags().StringVar(&authPassword, "password", "", "Senha para autenticação básica")
	RootCmd.PersistentFlags().BoolVar(&ctfMode, "ctf", false, "Enable CTF-optimized mode (fast, stealthy, resource-efficient)")

}

// GetCTFMode returns the current CTF mode status
func GetCTFMode() bool {
	return ctfMode
}
