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

var ScanCmd = &cobra.Command{
	Use:   "scan <target>",
	Short: "Performs vulnerability scanning on a target",
	Long: `The 'scan' command runs a series of vulnerability scanning tools against a target that has already been processed by the 'recon' command. It relies on the output of the reconnaissance phase (like live subdomains and technology information). This command is the second step in a typical assessment workflow.
Usage Examples:
redrecon scan example.com
redrecon scan --results-dir results/my-task-name
redrecon scan --results-dir results/
redrecon scan example.com --only nuclei,cvesearch
redrecon scan example.com --skip bbot
redrecon scan example.com --aggressive`,
	RunE: func(cmd *cobra.Command, args []string) error {
		logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
		taskIdentifiers := make(map[string]struct{})

		if scanResultsDir != "" {
			slog.Info("Scanning based on provided results directory", "dir", scanResultsDir)
			info, err := os.Stat(scanResultsDir)
			if err != nil {
				return fmt.Errorf("não foi possível acessar o diretório de resultados '%s': %w", scanResultsDir, err)
			}

			if !info.IsDir() {
				return fmt.Errorf("--results-dir must point to a directory")
			}

			reconPath := filepath.Join(scanResultsDir, "recon")
			if _, err := os.Stat(reconPath); err != nil && filepath.Base(scanResultsDir) == "recon" {
				reconPath = scanResultsDir
			}
			if _, err := os.Stat(reconPath); err == nil {
				taskName := filepath.Base(scanResultsDir)
				taskIdentifiers[taskName] = struct{}{}
			} else { // Se não for um diretório de tarefa, assume que é um diretório pai.
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
			if len(args) > 0 {
				scanTarget = args[0]
			}
			if scanTarget == "" {
				return fmt.Errorf("a task name or --results-dir must be specified for the scan command")
			}
			taskIdentifiers[scanTarget] = struct{}{}
		}

		for taskID := range taskIdentifiers {
			slog.Info("===== STARTING SCAN =====", "task_identifier", taskID)
			summary, _, err := scan.StartScan(cmd.Context(), taskID, "", scanSkipSteps, scanOnlySteps, scanAggressive, true, logger)
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