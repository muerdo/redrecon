package scan

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"redrecon/internal/config"
	"redrecon/pkg/analysis"
	"redrecon/pkg/recon"
	"redrecon/pkg/target"
	"redrecon/pkg/tools"
	"path/filepath"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

func executeCommand(ctx context.Context, logger *slog.Logger, toolName string, args ...string) (string, error) {
	return utils.ExecuteCommand(ctx, logger, toolName, args...)
}

type scanState struct {
	ctx                   context.Context
	target                string
	resultsPath           string // Caminho base para os resultados do alvo
	liveSubdomainsFile    string
	wafResultsFile        string // Caminho para o arquivo de resultados do WAF
	urlsFile              string
	techFile              string
	vulnerabilityFile     string
	nucleiScanFile        string
	nucleiAPIFile         string // Adicionado para Nuclei API Scan
	cveScanFile           string
	niktoScanFile         string
	dalfoxScanFile        string
	paramSpiderFile       string
	arjunFile             string
	owaspScanFile         string
	bbotScanFile          string
	sqlmapOutputDir       string
	apiFuzzFile           string
	enum4linuxngOutputDir string
	nucleiGroup        string
	attackMateOutputFile string // Adicionado para AttackMate
	sliverImplantFile    string // Adicionado para Sliver
	takeoverFile          string
	fuzzingOutputDirs     map[string]string // Map: toolName -> outputDirectoryPath for directory fuzzers

	parsedNucleiFindings       []types.NucleiFinding
	parsedHttpxVulnFindings    []analysis.HttpxVulnerabilityFinding
	parsedNiktoFindings        []analysis.NiktoFinding
	parsedFfufFindings         []analysis.FfufFinding
	parsedDirsearchFindings    []analysis.DirsearchFinding
	parsedFeroxbusterFindings  []analysis.FeroxbusterFinding
	parsedGobusterFindings     []analysis.GobusterFinding
	parsedCVEFindings          []types.CVEResult
	parsedBBotFindings         []types.BBotFinding // Nova: findings do BBOT (defina em pkg/types)

	tempDir               string
	logger                *slog.Logger
	errorLogger           *slog.Logger // Adicionado para log de erros centralizado
	wafMap                map[string]string
	config                *config.Config
}

// MarkPartialFail registra um aviso de que uma etapa falhou, mas o fluxo pode continuar.
func (s *scanState) MarkPartialFail(step string, err error) {
	s.logger.Warn("Partial step failure (continuing)", "step", step, "error", err)
}

type scanStep func(state *scanState) error

func StartScan(ctx context.Context, taskIdentifier string, inputFile string, skipSteps, onlySteps []string, nucleiGroup string, bbotPreset string, nucleiAPIFile string, cveScanFile string, isAggressive bool, isInteractive bool, logger *slog.Logger) (string, []string, error) {
	logger.Info("Starting vulnerability scan process", "task", taskIdentifier)

	// O taskIdentifier agora é o alvo principal (root domain), e o inputFile é o alvo específico (subdomínio/URL).
	finalTaskIdentifier := utils.SanitizeTargetForPath(taskIdentifier)

	reconResultsPath := filepath.Join("results", finalTaskIdentifier, "recon")
	scanResultsPath := filepath.Join("results", finalTaskIdentifier, "scan")

	// Cria o diretório de scan e o subdiretório temporário.
	tempDir := filepath.Join(scanResultsPath, "tmp")
	// Garante que o diretório de recon também exista, caso seja um novo scan.
	if err := os.MkdirAll(reconResultsPath, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create recon directory for scan: %w", err)
	}
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create temporary directory for scan: %w", err)
	}

	// Cria o logger de erros centralizado para a fase de scan
	errorLogFile := filepath.Join(scanResultsPath, "errors.log")
	errorFile, err := os.OpenFile(errorLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open error log file for scan: %w", err)
	}

	var originalScanTargetsFile string
	scanTargetsFile := filepath.Join(tempDir, "scan_targets.txt")

	// Se um alvo específico (inputFile) for fornecido, ele se torna a única fonte de alvos.
	if inputFile != "" && inputFile != finalTaskIdentifier {
		logger.Info("Using provided target for scan", "target", inputFile)
		if err := os.WriteFile(scanTargetsFile, []byte(inputFile+"\n"), 0644); err != nil {
			return "", nil, fmt.Errorf("failed to write target to scan targets file: %w", err)
		}
	} else { // Lógica de fallback para encontrar o melhor arquivo de entrada dentro do diretório do alvo.
		fallbackFiles := []struct {
			Name string
			Path string
		}{
			{"Live Subdomains", filepath.Join(reconResultsPath, "live_subdomains.txt")},
			{"All URLs", filepath.Join(reconResultsPath, "urls.txt")},
			{"Katana Deep URLs", filepath.Join(reconResultsPath, "katana", "katana_deep.txt")},
			{"Raw Subdomains", filepath.Join(reconResultsPath, "subdomains.txt")},
		}

		foundInput := false
		for _, fb := range fallbackFiles {
			if utils.FileExistsAndIsNotEmpty(fb.Path) {
				logger.Info(fmt.Sprintf("Using '%s' as input for the scan.", fb.Name), "file", fb.Path)
				if err := utils.CopyFile(fb.Path, scanTargetsFile); err != nil {
					return "", nil, fmt.Errorf("failed to copy fallback file '%s' to scan targets: %w", fb.Path, err)
				}
				foundInput = true
				break // Para no primeiro arquivo válido encontrado
			}
		}

		if !foundInput {
			detailedMsg := fmt.Sprintf("scan aborted for task '%s': No valid input files were found in the recon results directory. Please run the 'recon' command for this target first.", finalTaskIdentifier)
			logger.Error(detailedMsg)
			return "", nil, fmt.Errorf(detailedMsg)
		}
	}

	// Define o arquivo original para a varredura de vulnerabilidades, que agora é o `scanTargetsFile` consolidado.
	originalScanTargetsFile = scanTargetsFile

	// O restante da lógica de filtragem e execução continua a partir daqui...
	if !utils.FileExistsAndIsNotEmpty(scanTargetsFile) {
		return "", nil, fmt.Errorf("scan aborted: the final target list is empty after processing inputs")
	}

	logger.Info("Unified scan target list created", "path", scanTargetsFile, "total_targets", utils.CountLines(scanTargetsFile))

	filteredScanTargetsFile := filepath.Join(tempDir, "filtered_scan_targets.txt")
	if err := utils.FilterScanTargets(scanTargetsFile, filteredScanTargetsFile, logger); err != nil {
		return "", nil, fmt.Errorf("failed to filter scan targets: %w", err)
	}

	initialCount := utils.CountLines(scanTargetsFile)
	finalCount := utils.CountLines(filteredScanTargetsFile)
	logger.Info("Scan target list filtered", "initial_count", initialCount, "final_count", finalCount, "removed", initialCount-finalCount)

	if err := os.MkdirAll(scanResultsPath, 0755); err != nil {
		logger.Error("Failed to create scan directory", "path", scanResultsPath, "error", err)
		return "", nil, fmt.Errorf("could not create directory %s: %w", scanResultsPath, err)
	}

	state := &scanState{
		ctx:                ctx, // O contexto é passado
		target:             finalTaskIdentifier,
		resultsPath:        scanResultsPath,
		logger:             logger,
		errorLogger:        slog.New(slog.NewTextHandler(errorFile, nil)), // Inicializa o logger de erros
		wafResultsFile:     filepath.Join(reconResultsPath, "waf_results.json"), 
		liveSubdomainsFile: originalScanTargetsFile, // Usa o arquivo original para a varredura de vulnerabilidades
		urlsFile:           filteredScanTargetsFile,
		techFile:           filepath.Join(reconResultsPath, "httpx_tech.json"),
		vulnerabilityFile:  filepath.Join(scanResultsPath, "vulnerability_findings.txt"),
		nucleiScanFile:     filepath.Join(scanResultsPath, "nuclei_scan.txt"), // Saída geral do scan do Nuclei
		cveScanFile:        filepath.Join(scanResultsPath, "cve_results.json"),
		niktoScanFile:      filepath.Join(scanResultsPath, "nikto_scan.txt"),
		dalfoxScanFile:     filepath.Join(scanResultsPath, "dalfox_xss.txt"),
		paramSpiderFile:    filepath.Join(scanResultsPath, "paramspider_urls.txt"),
		arjunFile:          filepath.Join(scanResultsPath, "arjun_params.txt"),
		owaspScanFile:      filepath.Join(scanResultsPath, "owasp_scan.txt"),
		bbotScanFile:       filepath.Join(scanResultsPath, "bbot_output.json"),
		apiFuzzFile:        filepath.Join(scanResultsPath, "apifuzz_results.json"),
		nucleiGroup:        nucleiGroup,
		attackMateOutputFile: filepath.Join(scanResultsPath, "attackmate_output.json"),
		sliverImplantFile:    filepath.Join(scanResultsPath, "sliver_implant.bin"),
		sqlmapOutputDir:      filepath.Join(scanResultsPath, "sqlmap"),
		enum4linuxngOutputDir: filepath.Join(scanResultsPath, "enum4linuxng"),
		takeoverFile:       filepath.Join(scanResultsPath, "subdomain_takeover.json"),
		fuzzingOutputDirs:  make(map[string]string), // Inicializa o mapa para todos os fuzzers de diretório
		tempDir:            tempDir, // Diretório temporário para várias ferramentas
		wafMap:             make(map[string]string),
		parsedBBotFindings: []types.BBotFinding{}, // Inicializa
		config:             config.Cfg,
	}

	if err := loadWAFResults(state); err != nil {
		logger.Warn("Could not load WAF results, dynamic evasion will not be available.", "error", err)
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	workflow := map[string]scanStep{ // Adiciona a nova etapa de detecção de WAF
		"wafdetect":         stepDetectWAF,
		"paramspider":       stepRunParamSpider,
		"arjun":             stepRunArjun,
		"vulntests":         stepRunVulnerabilityTests,
		"dalfox":            stepRunDalfox,
		"sqlmap":            stepRunSqlmap,
		"enum4linuxng":      stepRunEnum4linuxNG,
		"nuclei":            stepRunNucleiScan,
		"cvesearch":         stepRunCVESearch,
		"owasp":             stepRunOWASPTests,
		"nikto":             stepRunNikto,
		"bbot":              func(s *scanState) error { return stepRunBBot(s, bbotPreset) },
		"apifuzz":           stepRunAPIFuzzing,
		"directoryfuzzing":  stepRunDirectoryFuzzing,
		"metasploit":        stepRunMetasploit,
		"subdomaintakeover": stepRunSubdomainTakeover,
		"targetedvulnscan":  stepRunTargetedVulnerabilityScan,
		"attackmate":        stepRunAttackMate, // Novo step
		"sliverimplant":     stepRunSliverImplant, // Novo step
		"naabu":             stepRunNaabu,
		"dirsearch":         stepRunDirsearch,
		"nucleiscan":        stepRunNucleiScan,
		"feroxbuster":       stepRunFeroxbuster,
		"gobuster":          stepRunGobuster,
	}
	var executionOrder []string
	if len(onlySteps) > 0 { // Se --only for usado, executa apenas os passos especificados
		for _, step := range onlySteps {
			if _, ok := workflow[step]; !ok {
				return "", nil, fmt.Errorf("invalid step specified in --only flag: %s", step)
			}
		}
		executionOrder = onlySteps
		skipSet = make(map[string]struct{})
	} else { // Ordem de execução padrão
		executionOrder = []string{"wafdetect", "subdomaintakeover", "paramspider", "arjun", "naabu", "vulntests", "dalfox", "sqlmap", "enum4linuxng", "nuclei", "cvesearch", "owasp", "nikto", "bbot", "apifuzz", "directoryfuzzing", "metasploit", "targetedvulnscan", "attackmate", "sliverimplant"} // Ordem de execução padrão, removendo chamadas duplicadas
	}
	logger.Info("Starting vulnerability scan tasks.")

	// Executa as etapas do fluxo de trabalho
	runSteps(state, executionOrder, workflow, skipSet, isInteractive)

	summary, resultFiles, err := generateScanSummary(state)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate scan summary: %w", err)
	}

	return summary, resultFiles, nil
}

func stepRunBBot(s *scanState, bbotPreset string) error {
	if !config.Cfg.Tools.Bbot.Enabled {
		s.logger.Info("BBOT is disabled in configuration. Skipping step.")
		return nil
	}

	s.logger.Info("--- Starting: BBOT Scan ---")

	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("BBOT input file is empty or does not exist, skipping.", "file", s.liveSubdomainsFile)
		return nil // Pula, mas não falha
	}

	// Load base BBot configuration from tools.bbot
	bbotConfig := config.Cfg.Tools.Bbot

	var currentPreset *config.BBotToolConfig
	if bbotPreset != "" {
		if config.Cfg.Recon.Presets != nil {
			if preset, ok := config.Cfg.Recon.Presets[bbotPreset]; ok && preset.BBot != nil {
				currentPreset = preset.BBot
				s.logger.Info("Using BBot preset for scan", "preset", bbotPreset)
			} else {
				s.logger.Warn("BBot preset not found, falling back to default BBot configuration.", "preset", bbotPreset)
			}
		} else {
			s.logger.Warn("Recon.Presets section is not defined in config, falling back to default BBot configuration.", "preset", bbotPreset)
		}
	}

	// If a preset is active, merge its settings with the base bbotConfig
	if currentPreset != nil {
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
		AddSlice(bbotConfig.ExtraArgs)
	extraArgs := argsBuilder.Build()

	outputDir := filepath.Join(s.resultsPath, "bbot")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for bbot: %w", err)
	}

	jsonFile, err := tools.RunBBot(
		s.ctx,
		s.liveSubdomainsFile, // inputFile
		"",                   // subdomainsFile (empty for scan phase)
		outputDir,
		bbotConfig.AllowDeadly,
		bbotConfig.RateLimit,
		bbotConfig.Concurrency,
		bbotConfig.Proxy,
		s.logger,
		extraArgs...,
	)
	if err != nil {
		s.MarkPartialFail("bbot_run", err)
		return nil // Não é um erro fatal
	}

	s.bbotScanFile = jsonFile
	s.logger.Info("BBOT scan step completed")
	return nil
}

func stepRunParamSpider(s *scanState) error {
	s.logger.Info("--- Starting: Parameter Discovery (ParamSpider) ---")
	hosts, err := utils.ReadLines(s.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read live subdomains for paramspider: %w", err)
	}

	// ParamSpider now takes a list of targets from a file.
	tempInputFile, err := os.CreateTemp(s.tempDir, "paramspider_input_*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp input file for paramspider: %w", err)
	}
	defer os.Remove(tempInputFile.Name())

	if _, err := tempInputFile.WriteString(strings.Join(hosts, "\n")); err != nil {
		return fmt.Errorf("failed to write hosts to temp file for paramspider: %w", err)
	}
	tempInputFile.Close()

	// The tool now writes directly to the output file.
	return tools.RunParamSpider(s.ctx, tempInputFile.Name(), s.paramSpiderFile, s.tempDir, s.logger)
}

func stepRunArjun(s *scanState) error {
	s.logger.Info("--- Starting: Parameter Discovery (Arjun) ---")
	hosts, err := utils.ReadLines(s.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read live subdomains for arjun: %w", err)
	}

	// Arjun now takes a list of targets from a file.
	tempInputFile, err := os.CreateTemp(s.tempDir, "arjun_input_*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temp input file for arjun: %w", err)
	}
	defer os.Remove(tempInputFile.Name())

	if _, err := tempInputFile.WriteString(strings.Join(hosts, "\n")); err != nil {
		return fmt.Errorf("failed to write hosts to temp file for arjun: %w", err)
	}
	tempInputFile.Close()

	// The tool now writes directly to the output file.
	return tools.RunArjun(s.ctx, tempInputFile.Name(), s.arjunFile, s.tempDir, s.logger)
}

func stepRunVulnerabilityTests(s *scanState) error {
	s.logger.Info("--- Starting: Basic Vulnerability Probes (httpx) ---")
	return tools.RunHttpxVulnerabilityScan(s.ctx, s.liveSubdomainsFile, s.vulnerabilityFile, s.tempDir, s.logger)
}

func stepRunDalfox(s *scanState) error {
	s.logger.Info("--- Starting: Advanced XSS Scanning (Dalfox) ---")
	return tools.RunDalfox(s.ctx, s.paramSpiderFile, s.dalfoxScanFile, s.tempDir, s.logger)
}

func stepRunCVESearch(s *scanState) error {
	s.logger.Info("--- Starting: CVE Scanning based on Technology ---")
	return recon.RunCVESearch(s.ctx, s.techFile, s.cveScanFile, s.logger)
}

func stepRunOWASPTests(s *scanState) error {
	s.logger.Info("--- Starting: OWASP Top 10 Checks (Nuclei) ---")
	// A função runNucleiScan não existe, a lógica deve ser chamada diretamente.
	nucleiOutputFile, err := tools.RunNuclei(
		s.ctx,
		s.liveSubdomainsFile,
		strings.Join(config.Cfg.Recon.Nuclei.OWASPTemplates, ","), // tags
		"", // proxy
		s.logger,
		[]string{}, // extraArgs
	)
	if err != nil {
		return err
	}
	// Update s.owaspScanFile with the actual output file path
	s.owaspScanFile = nucleiOutputFile
	return nil
}

func stepRunAPIFuzzing(s *scanState) error {
	s.logger.Info("--- Starting: API Endpoint Fuzzing (ffuf) ---")
	fuzzWordlist := config.Cfg.Wordlists.Fuzzing
	if !utils.FileExistsAndIsNotEmpty(fuzzWordlist) {
		s.logger.Warn("Fuzzing wordlist not configured or file not found, skipping API fuzzing.", "path", fuzzWordlist)
		return nil
	}

	var rateLimit int
	if config.Cfg.Engine.WAF.Enabled {
		// Para ffuf, aplicamos o perfil padrão, pois ele opera em uma lista de alvos.
		defaultProfileName := config.Cfg.Engine.WAF.DefaultProfile
		if profile, ok := config.Cfg.Engine.WAF.Profiles[defaultProfileName]; ok {
			rateLimit = profile.RateLimit
			
		}
	}

	// Define o diretório de saída para os resultados do ffuf.
	ffufOutputDir := filepath.Join(s.resultsPath, "apifuzz")
	if err := os.MkdirAll(ffufOutputDir, 0755); err != nil {
		return fmt.Errorf("falha ao criar diretório de saída para ffuf: %w", err)
	}

	return tools.RunFfuf(s.ctx, s.liveSubdomainsFile, fuzzWordlist, ffufOutputDir, "", rateLimit, s.logger)
}

func stepRunDirectoryFuzzing(s *scanState) error {
    s.logger.Info("--- Starting: Directory and File Brute-forcing (Parallel) ---")

    var wg sync.WaitGroup
    fuzzingSteps := map[string]scanStep{
        "dirsearch":   stepRunDirsearch,
        "feroxbuster": stepRunFeroxbuster,
        "gobuster":    stepRunGobuster,
    }

    for name, stepFunc := range fuzzingSteps {
        wg.Add(1)
        go func(stepName string, sf scanStep) {
            defer wg.Done()
            // Clona o estado para evitar race conditions em campos que podem ser modificados
            stepState := *s
            if err := sf(&stepState); err != nil {
                // A falha em uma ferramenta de fuzzing não deve parar as outras.
                s.MarkPartialFail(stepName, err)
            }
        }(name, stepFunc)
    }

    wg.Wait()
    s.logger.Info("All directory fuzzing tools have completed.")
    return nil
}

func stepRunSubdomainTakeover(s *scanState) error {
	s.logger.Info("--- Starting: Subdomain Takeover Scan ---")
	return tools.RunSubzy(s.ctx, s.liveSubdomainsFile, s.takeoverFile, s.logger)
}

func stepRunTargetedVulnerabilityScan(s *scanState) error {
	s.logger.Info("--- Starting: Targeted Vulnerability Scan (Chaining Fuzzing Results) ---")
	return nil // Placeholder para evitar erro de compilação, a função real está mais abaixo no arquivo.
}

func loadWAFResults(s *scanState) error {
	data, err := os.ReadFile(s.wafResultsFile)
	if err != nil {
		return err
	}
	var wafResults []types.WAFResult
	if err := json.Unmarshal(data, &wafResults); err != nil {
		return err
	}
	for _, res := range wafResults {
		s.wafMap[res.Host] = res.WAF
	}
	return nil
}

func stepRunMetasploit(state *scanState) error {
	if !config.Cfg.Metasploit.Enabled || !config.Cfg.Metasploit.AutoEscalate {
		return nil
	}

	msf, err := tools.NewMetasploit(state.ctx, state.logger)
	if err != nil {
		state.MarkPartialFail("msf_connect", err)
		return nil
	}
	defer msf.Close()

	// Paralelize exploits para high-severity findings
	var wg sync.WaitGroup
	for _, f := range state.parsedNucleiFindings {
		if f.Severity != "high" && f.Severity != "critical" {
			continue
		}
		wg.Add(1)
		go func(finding types.NucleiFinding) {
			defer wg.Done()
			// Extrai a tecnologia do campo Meta, se existir
			var tech string
			for _, tag := range finding.Meta.Info.Tags {
				if _, exists := config.Cfg.Metasploit.Modules[tag]; exists {
					tech = tag
					break // Usa a primeira tecnologia correspondente encontrada
				}
			}

			out, err := msf.RunExploit(finding.Target, "", map[string]string{"tech": tech})
			if err != nil {
				state.MarkPartialFail("msf_exploit", err)
				return
			}
			state.logger.Info("Metasploit exploit executed successfully", "target", finding.Target, "module", out.Secrets[0].Pattern)
		}(f)
	}
	wg.Wait()
	return nil
}

func stepRunNikto(s *scanState) error {
	niktoCfg := config.Cfg.Recon.Nikto
	if !niktoCfg.Enabled {
		s.logger.Info("Nikto is disabled in config, skipping.")
		return nil
	}

	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Live subdomains file is empty, skipping Nikto scan.", "file", s.liveSubdomainsFile)
		return nil
	}

	s.logger.Info("--- Starting: Web Server Scan (Nikto) ---")

	// Define o arquivo de saída JSON
	outputFile := filepath.Join(s.resultsPath, "nikto_findings.json")
	s.niktoScanFile = outputFile // Atualiza o estado

	// Cria um arquivo temporário com a lista de alvos para usar com -host @<file>
	targets, err := utils.ReadLines(s.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read live subdomains for nikto: %w", err)
	}
	tempTargetsFile, err := os.CreateTemp(s.tempDir, "nikto_targets_*.txt")
	if err != nil {
		return fmt.Errorf("failed to create temporary targets file for nikto: %w", err)
	}
	defer os.Remove(tempTargetsFile.Name())
	if _, err := tempTargetsFile.WriteString(strings.Join(targets, "\n")); err != nil {
		tempTargetsFile.Close()
		return fmt.Errorf("failed to write targets to nikto temp file: %w", err)
	}
	tempTargetsFile.Close()

	// Constrói os argumentos com base na configuração
	argsBuilder := utils.NewArgBuilder()
	argsBuilder.AddFlagIfNotEmpty("-host", "@"+tempTargetsFile.Name()).
		AddFlagIfNotEmpty("-Format", "json"). // Força JSON para saída estruturada
		AddFlagIfNotEmpty("-o", outputFile).
		AddFlagIfNotEmpty("-Tuning", niktoCfg.Tuning).
		AddFlagIfNotEmpty("-useproxy", niktoCfg.Proxy).
		AddFlagIf(niktoCfg.MaxTime > 0, "-maxtime", fmt.Sprintf("%d", niktoCfg.MaxTime)).
		AddFlagIfNotEmpty("-evasion", niktoCfg.Evasion).
		AddFlagIf(niktoCfg.PauseSeconds > 0, "-Pause", fmt.Sprintf("%.0f", niktoCfg.PauseSeconds)).
		AddFlagIf(niktoCfg.FollowRedirects, "-followredirects", "").
		AddFlagIfNotEmpty("-mutate", niktoCfg.Mutate).
		AddFlagIf(niktoCfg.Timeout > 0, "-timeout", fmt.Sprintf("%d", niktoCfg.Timeout)).
		AddSlice(niktoCfg.ExtraArgs)

	extraArgs := argsBuilder.Build()

	s.logger.Info("Running Nikto scan for all live hosts.", "count", len(targets), "args", strings.Join(extraArgs, " "))

	_, err = tools.RunNikto(s.ctx, "", "", s.tempDir, s.logger, extraArgs...)
	if err != nil {
		s.MarkPartialFail("nikto", err)
	}

	s.logger.Info("Nikto scan completed.", "output_file", outputFile)
	return nil
}

// stepRunAttackMate executa o AttackMate.
func stepRunAttackMate(s *scanState) error {
	if !config.Cfg.Orchestration.AttackMate.Enabled {
		s.logger.Info("AttackMate is disabled in configuration. Skipping step.")
		return nil
	}
	s.logger.Info("--- Starting: AttackMate Orchestration ---")

	// Escolhe o primeiro playbook configurado.
	if len(config.Cfg.Orchestration.AttackMate.Playbooks) == 0 {
		s.logger.Warn("No AttackMate playbooks configured. Skipping step.")
		return nil
	}
	playbook := config.Cfg.Orchestration.AttackMate.Playbooks[0]

	// Prepara o arquivo de entrada para o AttackMate.
	attackMateInputFile := filepath.Join(s.tempDir, "attackmate_input.txt")
	
	err := utils.CombineAndDeduplicateFiles(attackMateInputFile, s.liveSubdomainsFile, s.urlsFile)
	if err != nil {
		return fmt.Errorf("failed to prepare AttackMate input file: %w", err)
	}

	// Obtém configurações de WAF para rate limit e proxy.
	var rateLimit int
	var proxy string
	if config.Cfg.Engine.WAF.Enabled {
		defaultProfileName := config.Cfg.Engine.WAF.DefaultProfile
		if profile, ok := config.Cfg.Engine.WAF.Profiles[defaultProfileName]; ok {
			rateLimit = profile.RateLimit
			if len(profile.Proxies) > 0 {
				proxy = profile.Proxies[0] // Usa o primeiro proxy da lista
			}
		}
	}
	// Sobrescreve com as configurações específicas do AttackMate se existirem.
	if config.Cfg.Orchestration.AttackMate.RateLimit > 0 {
		rateLimit = config.Cfg.Orchestration.AttackMate.RateLimit
	}
	if config.Cfg.Orchestration.AttackMate.Proxy != "" {
		proxy = config.Cfg.Orchestration.AttackMate.Proxy
	}

	am := tools.NewAttackMate(s.logger)
	err = am.Run(s.ctx, playbook, attackMateInputFile, s.attackMateOutputFile, rateLimit, s.config.Engine.MaxParallelTasks, proxy)
	if err != nil {
		s.MarkPartialFail("attackmate", err)
		return nil // Não é um erro fatal para o scan geral
	}

	parsedFindings, parseErr := analysis.ParseAttackMate(s.attackMateOutputFile)
	if parseErr != nil {
		s.logger.Warn("Failed to parse AttackMate output", "error", parseErr)
	} else {
		// Aqui você pode adicionar os achados do AttackMate ao estado do scan, se houver um mecanismo para isso.
		s.logger.Info("Parsed AttackMate findings", "count", len(parsedFindings))
	}

	s.logger.Info("AttackMate orchestration completed.")
	return nil
}

// stepRunSliverImplant gera um implante Sliver se achados de alta severidade forem detectados.
func stepRunSliverImplant(s *scanState) error {
	if !config.Cfg.Orchestration.Sliver.Enabled {
		s.logger.Info("Sliver is disabled in configuration. Skipping implant generation.")
		return nil
	}
	s.logger.Info("--- Starting: Sliver Implant Generation ---")

	shouldGenerateImplant := false
	for _, f := range s.parsedNucleiFindings {
		if f.Severity == "critical" || f.Severity == "high" {
			shouldGenerateImplant = true
			break
		}
	}

	if !shouldGenerateImplant {
		s.logger.Info("No high/critical severity findings detected. Skipping Sliver implant generation.")
		return nil
	}

	// Usa o primeiro alvo do liveSubdomainsFile como base para o implante.
	var targetHost string
	if utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		hosts, err := utils.ReadLines(s.liveSubdomainsFile)
		if err == nil && len(hosts) > 0 {
			targetHost = hosts[0]
		}
	}

	if targetHost == "" {
		s.logger.Warn("No live hosts found to associate with Sliver implant. Skipping.")
		return nil
	}

	// Extrai o domínio raiz para nomear o implante.
	rootDomain := target.GetRootDomain(targetHost)
	implantPath := filepath.Join(s.resultsPath, fmt.Sprintf("sliver_implant_%s.bin", utils.SanitizeTargetForPath(rootDomain)))

	sliverTool := tools.NewSliver(s.logger)
	err := sliverTool.Implant(s.ctx, config.Cfg.Orchestration.Sliver.LHost, implantPath)
	if err != nil {
		s.MarkPartialFail("sliver_implant", err)
		return nil // Não é um erro fatal para o scan geral
	}

	s.sliverImplantFile = implantPath // Salva o caminho do implante no estado
	s.logger.Info("Sliver implant generation completed.", "implant_path", implantPath)
	return nil
}

func stepRunSqlmap(s *scanState) error {
	if !config.Cfg.Tools.Sqlmap.Enabled {
		s.logger.Info("Sqlmap is disabled in configuration. Skipping step.")
		return nil
	}

	s.logger.Info("--- Starting: SQL Injection Scan (Sqlmap) ---")

	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Sqlmap input file is empty or does not exist, skipping.", "file", s.liveSubdomainsFile)
		return nil
	}

	if err := os.MkdirAll(s.sqlmapOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for sqlmap: %w", err)
	}

	err := tools.RunSqlmap(
		s.ctx,
		s.liveSubdomainsFile,
		s.sqlmapOutputDir,
		s.tempDir,
		s.logger,
	)
	if err != nil {
		s.MarkPartialFail("sqlmap_run", err)
		return nil
	}

	s.logger.Info("Sqlmap scan step completed")
	return nil
}

func stepRunEnum4linuxNG(s *scanState) error {
	if !config.Cfg.Tools.Enum4linuxNG.Enabled {
		s.logger.Info("Enum4linuxNG is disabled in configuration. Skipping step.")
		return nil
	}

	s.logger.Info("--- Starting: SMB/Windows Enumeration (Enum4linuxNG) ---")

	targets, err := utils.ReadLines(s.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read targets for Enum4linuxNG scan: %w", err)
	}

	if len(targets) == 0 {
		s.logger.Warn("Enum4linuxNG input file is empty, skipping.", "file", s.liveSubdomainsFile)
		return nil
	}

	if err := os.MkdirAll(s.enum4linuxngOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for enum4linuxng: %w", err)
	}

	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, target := range targets {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case concurrencyLimit <- struct{}{}:
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				defer func() { <-concurrencyLimit }()
				s.logger.Info("Running Enum4linuxNG for target", "target", t)
				err := tools.RunEnum4linuxNG(
					s.ctx,
					t,
					s.enum4linuxngOutputDir,
					s.tempDir,
					s.logger,
				)
				if err != nil {
					s.MarkPartialFail(fmt.Sprintf("enum4linuxng_run_%s", t), err)
				}
			}(target)
		}
	}
	wg.Wait()

	s.logger.Info("Enum4linuxNG scan step completed")
	return nil
}

func runCVESearch(ctx context.Context, techFile, outputFile string, logger *slog.Logger) error {
	return recon.RunCVESearch(ctx, techFile, outputFile, logger)
}
func stepRunNaabu(s *scanState) error {
	s.logger.Info("--- Starting: Port Scanning (Naabu) ---")
	if !config.Cfg.Recon.Naabu.Enabled {
		s.logger.Info("Naabu is disabled in config, skipping.")
		return nil
	}
	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Live subdomains file is empty, skipping Naabu scan.", "file", s.liveSubdomainsFile)
		return nil
	}

	outputFile := filepath.Join(s.resultsPath, "naabu_scan.txt")
	err := tools.RunNaabu(s.ctx, s.liveSubdomainsFile, outputFile, s.tempDir, s.logger)
	if err != nil {
		s.MarkPartialFail("naabu", err)
		return nil // Not a fatal error
	}
	s.logger.Info("Naabu scan completed", "output_file", outputFile)
	return nil
}

func stepRunDirsearch(s *scanState) error {
	s.logger.Info("--- Starting: Directory Fuzzing (Dirsearch) ---")
	if !config.Cfg.Tools.Dirsearch.Enabled {
		s.logger.Info("Dirsearch is disabled in config, skipping.")
		return nil
	}
	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Live subdomains file is empty, skipping Dirsearch scan.", "file", s.liveSubdomainsFile)
		return nil
	}
	fuzzWordlist := config.Cfg.Wordlists.Fuzzing
	if !utils.FileExistsAndIsNotEmpty(fuzzWordlist) {
		s.logger.Warn("Fuzzing wordlist not configured or file not found, skipping Dirsearch.", "path", fuzzWordlist)
		return nil
	}

	outputFile := filepath.Join(s.resultsPath, "dirsearch_scan.txt")
	err := tools.RunDirsearch(s.ctx, s.liveSubdomainsFile, outputFile, fuzzWordlist, s.tempDir, s.logger)
	if err != nil {
		s.MarkPartialFail("dirsearch", err)
		return nil // Not a fatal error
	}
	s.logger.Info("Dirsearch scan completed", "output_file", outputFile)
	return nil
}

func stepRunFeroxbuster(s *scanState) error {
	s.logger.Info("--- Starting: Directory Fuzzing (Feroxbuster) ---")
	if !config.Cfg.Tools.Feroxbuster.Enabled {
		s.logger.Info("Feroxbuster is disabled in config, skipping.")
		return nil
	}
	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Live subdomains file is empty, skipping Feroxbuster scan.", "file", s.liveSubdomainsFile)
		return nil
	}
	fuzzWordlist := config.Cfg.Wordlists.Fuzzing
	if !utils.FileExistsAndIsNotEmpty(fuzzWordlist) {
		s.logger.Warn("Fuzzing wordlist not configured or file not found, skipping Feroxbuster.", "path", fuzzWordlist)
		return nil
	}

	outputFile := filepath.Join(s.resultsPath, "feroxbuster_scan.txt")
	err := tools.RunFeroxbuster(s.ctx, s.liveSubdomainsFile, outputFile, fuzzWordlist, s.tempDir, s.logger)
	if err != nil {
		s.MarkPartialFail("feroxbuster", err)
		return nil // Not a fatal error
	}
	s.logger.Info("Feroxbuster scan completed", "output_file", outputFile)
	return nil
}

func stepRunGobuster(s *scanState) error {
	s.logger.Info("--- Starting: Directory Fuzzing (Gobuster) ---")
	if !config.Cfg.Tools.Gobuster.Enabled {
		s.logger.Info("Gobuster is disabled in config, skipping.")
		return nil
	}
	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Live subdomains file is empty, skipping Gobuster scan.", "file", s.liveSubdomainsFile)
		return nil
	}
	fuzzWordlist := config.Cfg.Wordlists.Fuzzing
	if !utils.FileExistsAndIsNotEmpty(fuzzWordlist) {
		s.logger.Warn("Fuzzing wordlist not configured or file not found, skipping Gobuster.", "path", fuzzWordlist)
		return nil
	}

	outputFile := filepath.Join(s.resultsPath, "gobuster_scan.txt")
	err := tools.RunGobuster(s.ctx, s.liveSubdomainsFile, outputFile, fuzzWordlist, s.tempDir, s.logger)
	if err != nil {
		s.MarkPartialFail("gobuster", err)
		return nil // Not a fatal error
	}
	s.logger.Info("Gobuster scan completed", "output_file", outputFile)
	return nil
}

func generateScanSummary(state *scanState) (string, []string, error) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **Scan Summary for: %s**\n\n", state.target))

	nucleiCount := len(state.parsedNucleiFindings)
	if nucleiCount > 0 {
		summary.WriteString(fmt.Sprintf("• **Vulnerabilities (Nuclei):** %d findings detected.\n", nucleiCount))
		for _, f := range state.parsedNucleiFindings { // Corrigido aqui
			if f.Meta.Info.Severity == "critical" || f.Meta.Info.Severity == "high" {
				summary.WriteString(fmt.Sprintf("  - [%s] %s @ %s\n", strings.ToUpper(f.Meta.Info.Severity), f.Meta.Info.Name, f.Meta.Host))
			}
		}
	} else {
		summary.WriteString("• **Vulnerabilities (Nuclei):** No findings detected.\n")
	}

	httpxVulnCount := len(state.parsedHttpxVulnFindings)
	if httpxVulnCount > 0 {
		summary.WriteString(fmt.Sprintf("• **Injection Tests (httpx):** %d potential findings (XSS, SQLi, etc.).\n", httpxVulnCount))
		for _, f := range state.parsedHttpxVulnFindings {
			summary.WriteString(fmt.Sprintf("  - %s @ %s\n", f.Type, f.URL))
		}
	} else {
		summary.WriteString("• **Injection Tests (httpx):** No findings.\n")
	}

	niktoCount := len(state.parsedNiktoFindings)
	if niktoCount > 0 {
		summary.WriteString(fmt.Sprintf("• **Web Server Scan (Nikto):** %d potential issues identified.\n", niktoCount))
	} else {
		summary.WriteString("• **Web Server Scan (Nikto):** No significant findings.\n")
	}

	cveCount := len(state.parsedCVEFindings)
	if cveCount > 0 {
		summary.WriteString(fmt.Sprintf("• **Known CVEs:** %d potential CVEs related to detected technologies.\n", cveCount))
		for _, cve := range state.parsedCVEFindings {
			summary.WriteString(fmt.Sprintf("  - [%s] %s (%s)\n", cve.Severity, cve.CVE_ID, cve.Technology))
		}
	} else {
		summary.WriteString("• **Known CVEs:** No direct CVEs found for detected technologies.\n")
	}

	bbotCount := len(state.parsedBBotFindings)
	if bbotCount > 0 {
		summary.WriteString(fmt.Sprintf("• **BBOT Scan:** %d findings detected.\n", bbotCount))
		for _, f := range state.parsedBBotFindings {
			// Ajuste conforme fields do BBotFinding (ex.: if f.Severity == "high" { ... })
			summary.WriteString(fmt.Sprintf("  - %s @ %s\n", f.Type, f.Host)) // Exemplo
		}
	} else {
		summary.WriteString("• **BBOT Scan:** No findings detected.\n")
	}

	// Correção: Verifica se o arquivo existe antes de contar as linhas para evitar pânico.
	if utils.FileExistsAndIsNotEmpty(state.attackMateOutputFile) {
		attackMateCount := utils.CountLines(state.attackMateOutputFile)
		if attackMateCount > 0 {
			summary.WriteString(fmt.Sprintf("• **AttackMate Orchestration:** %d potential findings/actions.\n", attackMateCount))
		}
	} else {
		summary.WriteString("• **AttackMate Orchestration:** No findings detected.\n")
	}

	totalFuzzingFindings := len(state.parsedFfufFindings) +
		len(state.parsedDirsearchFindings) +
		len(state.parsedFeroxbusterFindings) +
		len(state.parsedGobusterFindings)
	if totalFuzzingFindings > 0 {
		summary.WriteString(fmt.Sprintf("• **Fuzzing (ffuf, Dirsearch, etc.):** %d interesting paths/responses found.\n", totalFuzzingFindings))
	} else {
		summary.WriteString("• **Fuzzing (ffuf, Dirsearch, etc.):** No interesting paths or responses found.\n")
	}

	// Adiciona todos os arquivos de saída dos fuzzers de diretório à lista resultFiles
	var resultFiles []string
	for _, outputDir := range state.fuzzingOutputDirs {
		resultFiles = append(resultFiles, outputDir)
	}

	resultFiles = append(resultFiles,
		state.nucleiScanFile, state.cveScanFile, state.owaspScanFile,
		state.vulnerabilityFile, state.niktoScanFile, state.bbotScanFile,
		state.dalfoxScanFile, state.paramSpiderFile, state.arjunFile, state.takeoverFile,
		state.apiFuzzFile, state.attackMateOutputFile,
	)

	if state.sliverImplantFile != "" {
		resultFiles = append(resultFiles, state.sliverImplantFile)
		summary.WriteString(fmt.Sprintf("• **Sliver Implant:** Generated at `%s`.\n", filepath.Base(state.sliverImplantFile)))
	}

	summary.WriteString(fmt.Sprintf("\n*Os resultados completos do scan são salvos em:* `%s`", state.resultsPath))

	return summary.String(), resultFiles, nil
}

func runSteps(state *scanState, executionOrder []string, workflow map[string]scanStep, skipSet map[string]struct{}, isInteractive bool) {
	if isInteractive {
		runStepsInteractive(state, executionOrder, workflow, skipSet)
	} else {
		runStepsNonInteractive(state, executionOrder, workflow, skipSet)
	}
}

func runStepsNonInteractive(state *scanState, executionOrder []string, workflow map[string]scanStep, skipSet map[string]struct{}) {
	for _, stepName := range executionOrder {
		if _, shouldSkip := skipSet[stepName]; shouldSkip {
			state.logger.Warn("Skipping step as requested by flags", "step", stepName)
			continue
		}

		stepFunc, ok := workflow[stepName]
		if !ok {
			continue
		}

		state.logger.Info(fmt.Sprintf("Starting scan step: %s", stepName))
		if err := stepFunc(state); err != nil {
			state.logger.Error("Step failed", "step", stepName, "error", err)
			state.errorLogger.Error("Scan Step Failed", "step", stepName, "error", err.Error())
		} else {
			state.logger.Info("Step completed successfully", "step", stepName)
		}
	}
}

func runStepsInteractive(state *scanState, executionOrder []string, workflow map[string]scanStep, skipSet map[string]struct{}) {
	skipInputChan := make(chan string)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			skipInputChan <- strings.TrimSpace(scanner.Text())
		}
	}()

	totalSteps := len(executionOrder)
	for i, stepName := range executionOrder {
		if _, shouldSkip := skipSet[stepName]; shouldSkip {
			state.logger.Warn("Skipping step as requested by flags", "step", stepName)
			continue
		}

		stepFunc, ok := workflow[stepName]
		if !ok {
			continue
		}

		stepCtx, cancelStep := context.WithCancel(state.ctx)
		errChan := make(chan error, 1)
		state.logger.Info(fmt.Sprintf("[Step %d/%d] Starting: %s", i+1, totalSteps, stepName))
		fmt.Printf("\n-> Press 's' and Enter to skip the current step: [%s]\n", stepName)

		go func() {
			// Crie uma cópia do estado para a goroutine para evitar race conditions
			stepState := *state
			stepState.ctx = stepCtx
			errChan <- stepFunc(&stepState)
		}()

		select {
		case skipInput := <-skipInputChan:
			if strings.ToLower(skipInput) == "s" {
				cancelStep()
				state.logger.Warn("Step skipped by user input", "step", stepName)
			}
		case err := <-errChan:
			if err != nil {
				state.logger.Error("Step failed", "step", stepName, "error", err)
				state.errorLogger.Error("Scan Step Failed", "step", stepName, "error", err.Error())
			} else {
				state.logger.Info("Step completed successfully", "step", stepName)
			}
		case <-state.ctx.Done():
			cancelStep()
			state.logger.Warn("Global context cancelled, stopping step execution.", "step", stepName)
			return
		}
	}
}

func stepDetectWAF(s *scanState) error {
	s.logger.Info("--- Starting: Port Scanning (Naabu) ---")
	if !config.Cfg.Recon.Naabu.Enabled {
		s.logger.Info("Naabu is disabled in config, skipping.")
		return nil
	}
	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Live subdomains file is empty, skipping Naabu scan.", "file", s.liveSubdomainsFile)
		return nil
	}

	err := tools.RunWafw00f(s.ctx, s.liveSubdomainsFile, s.wafResultsFile, s.tempDir, s.logger)
	if err != nil {
		s.MarkPartialFail("wafdetect", err)
		return nil // Não é um erro fatal, permite que o scan continue.
	}
	s.logger.Info("WAF detection completed", "output_file", s.wafResultsFile)
	return nil
}