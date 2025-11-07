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

	"gopkg.in/yaml.v2"
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

func StartAPI(taskIdentifier string, skipSteps []string, bbotPreset string, logger *slog.Logger) (string, []string, error) {
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
		"bbot":           func(s *apiState) error { return stepRunBBotAPI(s, bbotPreset) },
	}

	executionOrder := []string{"gathertargets", "specdiscovery", "apifuzz", "nucleiscan", "bbot"}

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
	state.logger.Info("Discovering API specification files (Swagger/OpenAPI) using configured fuzzing wordlist...")

	ffufOutputDir := filepath.Join(state.apiResultsPath, "ffuf_spec_results")
	if err := os.MkdirAll(ffufOutputDir, 0755); err != nil {
		return fmt.Errorf("falha ao criar diretório de saída para ffuf spec discovery: %w", err)
	}

	// Use the configured fuzzing wordlist directly
	fuzzWordlist := config.Cfg.Wordlists.Fuzzing
	if !utils.FileExistsAndIsNotEmpty(fuzzWordlist) {
		state.logger.Warn("Fuzzing wordlist not configured or file not found, skipping API spec discovery.", "path", fuzzWordlist)
		return nil
	}

	return tools.RunFfuf(state.ctx, state.apiTargetsFile, fuzzWordlist, ffufOutputDir, "", 0, state.logger)
}

func stepFuzzEndpoints(state *apiState) error {
	state.logger.Info("Fuzzing for API endpoints with Kiterunner...")
	state.logger.Warn("Kiterunner tool integration is not implemented yet. Skipping step.")
	return nil
}

func stepNucleiAPIScan(state *apiState) error {
	state.logger.Info("Scanning for API vulnerabilities with Nuclei...")
	apiTemplates := []string{"http/api/"}

	nucleiOutputFile, err := tools.RunNuclei(
		state.ctx,
		state.apiTargetsFile,
		strings.Join(apiTemplates, ","), // tags (string)
		"", // proxy (string)
		state.logger, // logger (*slog.Logger)
		[]string{}, // extraArgs ([]string)
	)
	if err != nil {
		return err
	}
	state.nucleiApiScanFile = nucleiOutputFile
	return nil
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

func stepRunBBotAPI(s *apiState, bbotPreset string) error {
	if !config.Cfg.Tools.Bbot.Enabled {
		s.logger.Info("BBOT is disabled in configuration. Skipping step.")
		return nil
	}

	if !utils.CommandExists("bbot") {
		s.logger.Error("bbot not installed or not executable. Check your PATH.", "tool", "bbot")
		return fmt.Errorf("bbot not found or not executable")
	}
	s.logger.Info("--- Starting: BBOT API Scan ---")

	targetInput := s.apiTargetsFile
	if !utils.FileExistsAndIsNotEmpty(targetInput) {
		s.logger.Warn("BBOT input file is empty or does not exist, skipping.", "file", targetInput)
		return nil // Skip, but don't fail
	}

	// Load base BBot configuration from tools.bbot
	bbotConfig := config.Cfg.Tools.Bbot

	var currentPreset *config.BBotToolConfig
	if bbotPreset != "" {
		// Garante que a seção de presets exista antes de tentar acessá-la.
		if config.Cfg.Recon.Presets != nil {
			if preset, ok := config.Cfg.Recon.Presets[bbotPreset]; ok && preset.BBot != nil {
				currentPreset = preset.BBot
				s.logger.Info("Using BBot preset for API scan", "preset", bbotPreset)
			} else {
				s.logger.Warn("BBot preset not found, falling back to default BBot configuration.", "preset", bbotPreset)
			}
		} else {
			s.logger.Warn("Recon.Presets section is not defined in config, falling back to default BBot configuration.", "preset", bbotPreset)
		}
	}

	// If a preset is active, merge its settings with the base bbotConfig
	if currentPreset != nil {
		// A lógica de merge que estava faltando foi adicionada aqui.
		if len(currentPreset.Presets) > 0 {
			bbotConfig.Presets = currentPreset.Presets
		}
		if len(currentPreset.Flags) > 0 {
			bbotConfig.Flags = currentPreset.Flags
		}
		if len(currentPreset.Modules) > 0 {
			bbotConfig.Modules = currentPreset.Modules
		}
		if len(currentPreset.OutputModules) > 0 {
			bbotConfig.OutputModules = currentPreset.OutputModules
		}
		if len(currentPreset.ExcludeModules) > 0 {
			bbotConfig.ExcludeModules = currentPreset.ExcludeModules
		}
		if len(currentPreset.Blacklist) > 0 {
			bbotConfig.Blacklist = currentPreset.Blacklist
		}
		if currentPreset.AllowDeadly {
			bbotConfig.AllowDeadly = true
		}
		if currentPreset.RateLimit > 0 {
			bbotConfig.RateLimit = currentPreset.RateLimit
		}
		if currentPreset.Concurrency > 0 {
			bbotConfig.Concurrency = currentPreset.Concurrency
		}
		if currentPreset.Proxy != "" {
			bbotConfig.Proxy = currentPreset.Proxy
		}
		if len(currentPreset.ExtraArgs) > 0 {
			bbotConfig.ExtraArgs = currentPreset.ExtraArgs
		}
		if len(currentPreset.ConfigOverrides) > 0 {
			bbotConfig.ConfigOverrides = currentPreset.ConfigOverrides
		}
	}

	// Handle config_overrides
	var tempConfigFile string
	if len(bbotConfig.ConfigOverrides) > 0 {
		tempFile, err := os.CreateTemp(s.tempDir, "bbot_config_override_*.yml")
		if err != nil {
			return fmt.Errorf("failed to create temporary config override file: %w", err)
		}
		// defer os.Remove(tempFile.Name()) // Desativado para depuração
		defer tempFile.Close()
		
		configBytes, err := yaml.Marshal(bbotConfig.ConfigOverrides)
		if err != nil {
			return fmt.Errorf("failed to marshal bbot config overrides: %w", err)
		}
		if _, err := tempFile.Write(configBytes); err != nil {
			return fmt.Errorf("failed to write bbot config overrides to temp file: %w", err)
		}
		tempConfigFile = tempFile.Name()
	}

	argsBuilder := utils.NewArgBuilder()
	for _, p := range bbotConfig.Presets {
		argsBuilder.AddFlagIfNotEmpty("-p", p)
	}
	for _, f := range bbotConfig.Flags {
		argsBuilder.AddFlagIfNotEmpty("-f", f)
	}
	for _, bl := range bbotConfig.Blacklist {
		argsBuilder.AddFlagIfNotEmpty("--blacklist", bl)
	}

	argsBuilder.AddFlagIf(len(bbotConfig.Modules) > 0, "-m", strings.Join(bbotConfig.Modules, ",")).
		AddFlagIf(len(bbotConfig.OutputModules) > 0, "--output-module", strings.Join(bbotConfig.OutputModules, ",")).
		AddFlagIf(len(bbotConfig.ExcludeModules) > 0, "--exclude-module", strings.Join(bbotConfig.ExcludeModules, ",")).
		AddFlagIf(bbotConfig.AllowDeadly, "--allow-deadly", "").
		AddFlagIf(bbotConfig.RateLimit > 0, "--rate-limit", fmt.Sprintf("%d", bbotConfig.RateLimit)).
		AddFlagIf(bbotConfig.Concurrency > 0, "--concurrency", fmt.Sprintf("%d", bbotConfig.Concurrency)).
		AddFlagIfNotEmpty("--proxy", bbotConfig.Proxy).
		AddSlice(bbotConfig.ExtraArgs).
		AddFlagIfNotEmpty("-c", tempConfigFile)
	extraArgs := argsBuilder.Build()

	outputDir := filepath.Join(s.apiResultsPath, "bbot")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for bbot: %w", err)
	}

	jsonFile, err := tools.RunBBot(
		s.ctx,
		targetInput,
		"", // subdomainsFile (empty for now)
		outputDir,
		bbotConfig.AllowDeadly,
		bbotConfig.RateLimit,
		bbotConfig.Concurrency,
		bbotConfig.Proxy,
		s.logger,
		extraArgs...,
	)
	if err != nil {
		s.logger.Error("BBOT API scan failed", "error", err)
		return nil // Not a fatal error
	}

	if jsonFile != "" && utils.FileExistsAndIsNotEmpty(jsonFile) {
		// Optionally parse BBot findings and add to API state
		// For now, just log that it completed
		s.logger.Info("BBOT API scan completed", "output_file", jsonFile)
	}

	return nil
}
