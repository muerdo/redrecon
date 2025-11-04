package cmd

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"os"

	"redrecon/pkg/scan"

	"github.com/spf13/cobra"
)

var (
	scanTarget  string
	scanSkipSteps []string
	scanOnlySteps []string
	scanAggressive bool
	scanResultsDir string
)

// ScanCmd represents the scan command
var ScanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Performs vulnerability scanning on a target",
	Long: `The 'scan' command runs a series of vulnerability scanning tools against a target
that has already been processed by the 'recon' command. It relies on the output
of the reconnaissance phase (like live subdomains and technology information).
This command is the second step in a typical assessment workflow.

Usage Examples:
  # Run a full vulnerability scan on a target (assumes 'recon' was run before)
  redrecon scan example.com

  # Run a scan by pointing directly to the results directory of a specific task
  redrecon scan --results-dir results/my-task-name

  # Run scans on ALL valid tasks found inside the 'results' directory
  redrecon scan --results-dir results/

  # Run the scan, but only execute the 'nuclei' and 'cvesearch' steps
  redrecon scan example.com --only nuclei,cvesearch

  # Run the scan, but skip the 'bbot' step
  redrecon scan example.com --skip bbot

  # Run an aggressive scan using bbot's 'kitchen-sink' profile
  redrecon scan example.com --aggressive`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		taskIdentifiers := make(map[string]struct{}) // Agora um set, pois o taskID é a única fonte da verdade.

		if scanResultsDir != "" {
			// Modo 2: O usuário especificou um diretório de resultados. Esta é a forma mais explícita.
			slog.Info("Scanning based on provided results directory", "dir", scanResultsDir)
			info, err := os.Stat(scanResultsDir)
			if err != nil {
				return fmt.Errorf("não foi possível acessar o diretório de resultados '%s': %w", scanResultsDir, err)
			}

			if !info.IsDir() {
				return fmt.Errorf("--results-dir must point to a directory")
			}

			// Verifica se o diretório fornecido é um diretório de tarefa (contém 'recon')
			// ou se é o próprio diretório 'recon'.
			reconPath := filepath.Join(scanResultsDir, "recon")
			if _, err := os.Stat(reconPath); err != nil && filepath.Base(scanResultsDir) == "recon" {
				reconPath = scanResultsDir // O usuário apontou diretamente para a pasta recon.
			}
			if _, err := os.Stat(reconPath); err == nil {
				// É um diretório de tarefa único.
				taskName := filepath.Base(scanResultsDir)
				taskIdentifiers[taskName] = struct{}{}
			} else { // Se não for um diretório de tarefa, assume que é um diretório pai.
				// É um diretório pai (como 'results/'). Procura por subdiretórios de tarefas.
				entries, err := os.ReadDir(scanResultsDir)
				if err != nil {
					return fmt.Errorf("could not read parent results directory %s: %w", scanResultsDir, err)
				}
				for _, entry := range entries {
					if entry.IsDir() {
						taskPath := filepath.Join(scanResultsDir, entry.Name())
						if _, err := os.Stat(filepath.Join(taskPath, "recon")); err == nil {
							taskIdentifiers[entry.Name()] = struct{}{}
						}
					}
				}
			}

			if len(taskIdentifiers) == 0 {
				slog.Warn("Nenhum diretório de resultado de 'recon' válido foi encontrado no caminho especificado.", "path", scanResultsDir)
				return nil
			}

		} else {
			// Modo legado: O usuário passa um ou mais nomes de tarefas como argumentos.
			if len(args) > 0 {
				scanTarget = args[0]
			}
			if scanTarget == "" {
				return fmt.Errorf("a task name or --results-dir must be specified for the scan command")
			}
			// Assume que o argumento é o nome da tarefa.
			taskIdentifiers[scanTarget] = struct{}{}
		}

		for taskID := range taskIdentifiers {
			slog.Info("===== STARTING SCAN =====", "task_identifier", taskID)
			// A chamada para StartScan agora é mais simples e lógica.
			summary, _, err := scan.StartScan(taskID, "", scanSkipSteps, scanOnlySteps, scanAggressive, true, logger) // true para interativo
			if err != nil {
				slog.Error("Vulnerability scan failed for task", "task_identifier", taskID, "error", err)
				continue
			}
			fmt.Println(summary)
		}

		return nil
	},
}

func init() {
	ScanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "Target for scanning (domain, file, or directory). Must have been processed by 'recon' first.")
	ScanCmd.Flags().StringVar(&scanResultsDir, "results-dir", "", "Path to an existing results directory to run the scan on. Can be a parent directory (e.g., 'results/').")
	ScanCmd.Flags().BoolVar(&scanAggressive, "aggressive", false, "Run bbot in aggressive mode ('kitchen-sink' preset).")
	ScanCmd.Flags().StringSliceVarP(&scanSkipSteps, "skip", "s", []string{}, "Comma-separated list of scan steps to skip (e.g., 'bbot,nikto').")
	ScanCmd.Flags().StringSliceVar(&scanOnlySteps, "only", []string{}, "Run ONLY the specified scan steps (e.g., 'nuclei,cvesearch').")
}