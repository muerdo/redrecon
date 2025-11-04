package api

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

type apiState struct {
	ctx              context.Context
	taskIdentifier   string
	reconResultsPath string
	infraResultsPath string
	apiResultsPath   string
	tempDir          string
	logger           *slog.Logger

	apiTargetsFile      string // Arquivo unificado de alvos para o scan de API
	specDiscoveryFile   string // Resultados da busca por swagger/openapi
	kiterunnerOutputFile string // Resultados do Kiterunner
	nucleiApiScanFile   string // Resultados do Nuclei para API
}

type apiStep func(state *apiState) error

func StartAPI(taskIdentifier string, skipSteps []string, logger *slog.Logger) (string, []string, error) {
	logger.Info("Starting API scan workflow", "task", taskIdentifier)

	sanitizedTaskIdentifier := utils.SanitizeTargetForPath(taskIdentifier)
	reconResultsPath := filepath.Join("results", sanitizedTaskIdentifier, "recon")
	infraResultsPath := filepath.Join("results", sanitizedTaskIdentifier, "infra")
	apiResultsPath := filepath.Join("results", sanitizedTaskIdentifier, "api")

	if err := os.MkdirAll(apiResultsPath, 0755); err != nil {
		return "", nil, fmt.Errorf("could not create API results directory: %w", err)
	}

	tempDir := filepath.Join(apiResultsPath, "tmp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create temporary directory for API scan: %w", err)
	}

	state := &apiState{
		ctx:              context.Background(),
		taskIdentifier:   taskIdentifier,
		reconResultsPath: reconResultsPath,
		infraResultsPath: infraResultsPath,
		apiResultsPath:   apiResultsPath,
		tempDir:          tempDir,
		logger:           logger,

		apiTargetsFile:      filepath.Join(tempDir, "api_targets.txt"),
		specDiscoveryFile:   filepath.Join(apiResultsPath, "spec_discovery.txt"),
		kiterunnerOutputFile: filepath.Join(apiResultsPath, "kiterunner_scan.txt"),
		nucleiApiScanFile:   filepath.Join(apiResultsPath, "nuclei_api_scan.txt"),
	}

	workflow := map[string]apiStep{
		"gathertargets":  stepGatherTargets,
		"specdiscovery":  stepDiscoverSpecs,
		"apifuzz":        stepFuzzEndpoints,
		"nucleiscan":     stepNucleiAPIScan,
	}

	executionOrder := []string{"gathertargets", "specdiscovery", "apifuzz", "nucleiscan"}

	for _, stepName := range executionOrder {
		stepFunc, ok := workflow[stepName]
		if !ok {
			logger.Error("Unknown API step in workflow", "step", stepName)
			continue
		}

		logger.Info(fmt.Sprintf("--- Starting API Step: %s ---", stepName))
		if err := stepFunc(state); err != nil {
			logger.Error("An API scan step failed, but continuing...", "step", stepName, "error", err)
		}
	}

	logger.Info("API scan process completed.")
	summary, files := generateAPISummary(state)
	return summary, files, nil
}

func stepGatherTargets(state *apiState) error {
	state.logger.Info("Gathering potential API targets from recon and infra results...")

	reconTargetsFile := filepath.Join(state.reconResultsPath, "recon_targets.txt")

	err := utils.CombineAndDeduplicateFiles(state.apiTargetsFile, reconTargetsFile)
	if err != nil {
		return fmt.Errorf("failed to combine recon targets: %w", err)
	}

	if !utils.FileExistsAndIsNotEmpty(state.apiTargetsFile) {
		return fmt.Errorf("no potential API targets found from previous stages")
	}

	state.logger.Info("API target list created", "path", state.apiTargetsFile, "count", utils.CountLines(state.apiTargetsFile))
	return nil
}

func stepDiscoverSpecs(state *apiState) error {
	state.logger.Info("Discovering API specification files (Swagger/OpenAPI)...")
	specWordlist := "swagger/swagger.json,openapi.json,openapi.yaml,v1/swagger.json,api/swagger.json"

	tempWordlistFile, err := os.CreateTemp(state.tempDir, "spec_wordlist_*.txt")
	if err != nil {
		return err
	}
	defer os.Remove(tempWordlistFile.Name())
	tempWordlistFile.WriteString(strings.ReplaceAll(specWordlist, ",", "\n"))
	tempWordlistFile.Close()

	ffufOutputDir := filepath.Join(state.apiResultsPath, "ffuf_spec_results")
	return tools.RunFfuf(state.ctx, state.apiTargetsFile, tempWordlistFile.Name(), ffufOutputDir, 0, state.logger)
}

func stepFuzzEndpoints(state *apiState) error {
	state.logger.Info("Fuzzing for API endpoints with Kiterunner...")
	state.logger.Warn("Kiterunner tool integration is not implemented yet. Skipping step.")
	return nil
}

func stepNucleiAPIScan(state *apiState) error {
	state.logger.Info("Scanning for API vulnerabilities with Nuclei...")
	apiTemplates := []string{"http/api/"}

	return tools.RunNuclei(state.ctx, state.apiTargetsFile, state.nucleiApiScanFile, state.tempDir, apiTemplates, config.Cfg.Engine.WAF.DefaultProfile, true, state.logger)
}

// generateAPISummary cria um resumo dos resultados da varredura de API.
func generateAPISummary(state *apiState) (string, []string) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **API Scan Summary for: %s**\n\n", state.taskIdentifier))
	files := []string{}

	if utils.FileExistsAndIsNotEmpty(state.nucleiApiScanFile) {
		summary.WriteString(fmt.Sprintf("• **Nuclei API Scan:** Findings saved to `%s`.\n", filepath.Base(state.nucleiApiScanFile)))
		files = append(files, state.nucleiApiScanFile)
	}

	summary.WriteString(fmt.Sprintf("\n*Full API scan results are saved in:* `%s`", state.apiResultsPath))
	return summary.String(), files
}
