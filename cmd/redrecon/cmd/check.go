package cmd

import (
	"fmt"
	"os"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var updateConfig bool

var CheckCmd = &cobra.Command{
	Use:   "check",
	Short: "Verifica se todas as ferramentas e dependências necessárias estão instaladas e configuradas.",
	Long: `O comando 'check' executa uma série de verificações para garantir que o ambiente está pronto para executar o RedRecon. Ele valida:
A presença e executabilidade de todas as ferramentas externas (ex: subfinder, httpx).
A existência dos arquivos de wordlist configurados.
A configuração de chaves de API para um desempenho ideal.
Use este comando para diagnosticar problemas de instalação ou configuração.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🔎 Executando verificação de ambiente do RedRecon...")

		if updateConfig {
			fmt.Println("📝 Tentando atualizar 'config.yaml' com os caminhos das ferramentas encontradas...")
			config.UpdateToolPathsInConfig()
			fmt.Println("✅ Verificação e atualização concluídas.")
			return // Encerra após a atualização.
		}

		// Verifica se o config.yaml existe
		if _, err := os.Stat("config.yaml"); os.IsNotExist(err) {
			fmt.Println(color.RedString("✗ Arquivo 'config.yaml' não encontrado. Crie um a partir de 'config.example.yaml'."))
			return
		}

		// Cores para a saída
		green := color.New(color.FgGreen).SprintFunc()
		red := color.New(color.FgRed).SprintFunc()
		yellow := color.New(color.FgYellow).SprintFunc()

		var allChecksPassed = true

		fmt.Println("\n--- Verificando Ferramentas Externas ---")
		toolsToCheck := config.GetAllToolKeys()
		for _, tool := range toolsToCheck {
			path := config.GetToolPath(tool)
			if utils.CommandExists(tool) {
				fmt.Printf("[%s] %-12s: Encontrada em %s\n", green("✓"), tool, path)
			} else {
				allChecksPassed = false
				fmt.Printf("[%s] %-12s: Não encontrada. Por favor, instale e adicione ao seu PATH.\n", red("✗"), tool)
			}
		}

		fmt.Println("\n--- Verificando Wordlists ---")
		wordlists := map[string]string{
			"Fuzzing": config.Cfg.Wordlists.Fuzzing, // A wordlist de subdomínios não é mais usada ativamente.
		}

		for name, path := range wordlists {
			if path == "" {
				fmt.Printf("[%s] Wordlist de %-10s: Não configurada em 'config.yaml'.\n", yellow("!"), name)
			} else if _, err := os.Stat(path); os.IsNotExist(err) {
				allChecksPassed = false
				fmt.Printf("[%s] Wordlist de %-10s: Arquivo não encontrado em '%s'.\n", red("✗"), name, path)
			} else {
				fmt.Printf("[%s] Wordlist de %-10s: Encontrada em '%s'.\n", green("✓"), name, path)
			}
		}

		fmt.Println("\n--- Verificando Chaves de API (Opcional, mas recomendado) ---")
		apiKeys := config.Cfg.APIKeys
		if apiKeys.Chaos == "" && apiKeys.SecurityTrails == "" && apiKeys.Shodan == "" && apiKeys.Github == "" {
			fmt.Printf("[%s] Nenhuma chave de API principal (Chaos, SecurityTrails, etc.) encontrada em 'config.yaml'.\n", yellow("!"))
			fmt.Println("      A enumeração de subdomínios será limitada. Adicione chaves para melhores resultados.")
		} else {
			var foundKeys []string
			if apiKeys.Chaos != "" { foundKeys = append(foundKeys, "Chaos") }
			if apiKeys.SecurityTrails != "" { foundKeys = append(foundKeys, "SecurityTrails") }
			if apiKeys.Shodan != "" { foundKeys = append(foundKeys, "Shodan") }
			if apiKeys.Github != "" { foundKeys = append(foundKeys, "GitHub") }
			fmt.Printf("[%s] Chaves de API encontradas para: %s.\n", green("✓"), strings.Join(foundKeys, ", "))
		}

		fmt.Println("\n" + strings.Repeat("=", 40))
		if allChecksPassed {
			fmt.Println(green("✅ Verificação concluída. Ambiente parece estar configurado corretamente!"))
		} else {
			fmt.Println(red("❌ Verificação concluída com erros. Por favor, corrija os itens marcados com [✗]."))
		}
	},
}

func init() {
	RootCmd.AddCommand(CheckCmd)
}
