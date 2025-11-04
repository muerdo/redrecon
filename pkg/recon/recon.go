package recon

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"log/slog"
	"math/rand"
	"os/exec"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"redrecon/pkg/analysis"
	"redrecon/pkg/utils"
	"redrecon/pkg/types"
	"redrecon/pkg/tools"
	"sync/atomic"
	
	"redrecon/internal/config"
	goexif "github.com/rwcarlsen/goexif/exif"
	"github.com/twmb/murmur3"
	"github.com/rwcarlsen/goexif/tiff"

	"rsc.io/pdf"
	"encoding/xml"
	"github.com/gocolly/colly/v2"

	_ "image/gif"  // Register GIF decoder
	_ "image/jpeg"
	_ "image/png"
)

var (
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api_key|apikey|token|secret|password|passwd|auth_token|bearer|client_secret|client_id)`),
		regexp.MustCompile(`(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`),
		regexp.MustCompile(`(sk|pk)_(test|live)_[0-9a-zA-Z]{24}`),
		regexp.MustCompile(`(SG\.[\w-]{22}\.[\w-]{43})`),
		regexp.MustCompile(`(AIza[0-9A-Za-z\-_]{35})`),
		regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`),
		regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['\"][0-9a-zA-Z\/\+]{40}['\"]`),
		regexp.MustCompile(`(?i)ghp_[0-9a-zA-Z]{36}`),
		regexp.MustCompile(`(?i)glpat-[0-9a-zA-Z_\-]{20}`),
		regexp.MustCompile(`-----BEGIN (RSA|EC|PGP|OPENSSH) PRIVATE KEY-----`),
		regexp.MustCompile(`(?i)(firebase|algolia|sentry|mixpanel|segment|google_api_key|gcp_api_key)`),
		regexp.MustCompile(`(?i)(jwt|jsonwebtokens)`),
		regexp.MustCompile(`(https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24})`),
	}

	endpointPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(/api/v[0-9]+|/v[0-9]+/api|/admin|/dashboard|/login|/auth|/graphql|/internal)`),
		regexp.MustCompile(`(?i)(\.php|\.asp|\.aspx|\.jsp|\.do|\.action|\.env|\.config|\.yml|\.yaml)`),
		regexp.MustCompile(`((http|https)://[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)+/api/[\w\./?=%&-]*)`),
	}

	sourceMappingURLRegex = regexp.MustCompile(`(?m)^//# sourceMappingURL=(.*)$`)
)

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 13_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
}

func getRandomUserAgent() string {
	return userAgents[rand.Intn(len(userAgents))]
}

type reconState struct {
	ctx                  context.Context
	target               string
	resultsPath          string
	subdomainsFile       string
	followRedirects      bool
	liveSubdomainsFile   string
	urlsFile             string
	jsFindingsFile       string
	reconTargetsFile     string
	techFile             string
	htmlFindingsFile     string
	fuzzWordlist         string
	
	parsedJSFindings   []types.URLFindings
	parsedHTMLFindings []types.URLFindings
	parsedFaviconHashes []types.FaviconResult
	
	ffufFindings       []analysis.FfufFinding
	dirsearchFindings  []analysis.DirsearchFinding
	tempDir              string
	logger               *slog.Logger
	errorLogger          *slog.Logger
}

// GetLiveSubdomainsFilePath retorna o caminho esperado para o arquivo live_subdomains.txt de um alvo.
func GetLiveSubdomainsFilePath(taskIdentifier string) string {
	sanitizedTaskIdentifier := utils.SanitizeTargetForPath(taskIdentifier)
	return filepath.Join("results", sanitizedTaskIdentifier, "recon", "live_subdomains.txt")
}

type reconStep func(state *reconState) error

func StartRecon(ctx context.Context, taskIdentifier string, rootTarget string, initialSubdomains []string, skipSteps []string, skipAnalysis bool, followRedirects bool, isInteractive bool, useResolvedForScan bool, logger *slog.Logger) (string, []string, bool, error) {
	slog.Info("Starting reconnaissance process", "target", rootTarget)

	sanitizedTaskIdentifier := utils.SanitizeTargetForPath(taskIdentifier)
	resultsPath := filepath.Join("results", sanitizedTaskIdentifier, "recon")
	slog.Info("Creating output directory", "path", resultsPath)

	if err := os.MkdirAll(resultsPath, 0755); err != nil && !os.IsExist(err) {
		slog.Error("Failed to create directory", "path", resultsPath, "error", err)
		return "", nil, false, fmt.Errorf("could not create directory %s: %w", resultsPath, err)
	}

	tempDir := filepath.Join(resultsPath, "tmp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", nil, false, fmt.Errorf("failed to create temporary directory for recon: %w", err)
	}

	errorLogFile := filepath.Join(resultsPath, "errors.log")
	errorFile, err := os.OpenFile(errorLogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return "", nil, false, fmt.Errorf("failed to open error log file: %w", err)
	}
	errorLogger := slog.New(slog.NewTextHandler(errorFile, nil))

	state := &reconState{
		ctx:                ctx,
		target:             rootTarget,
		resultsPath:        resultsPath,
		followRedirects:    followRedirects,
		subdomainsFile:     filepath.Join(resultsPath, "subdomains.txt"),
		liveSubdomainsFile: filepath.Join(resultsPath, "live_subdomains.txt"),
		urlsFile:           filepath.Join(resultsPath, "urls.txt"),
		reconTargetsFile:   filepath.Join(tempDir, "recon_targets.txt"),
		jsFindingsFile:     filepath.Join(resultsPath, "js_findings.txt"),
		logger:             logger, // Assign the custom logger
		techFile:           filepath.Join(resultsPath, "httpx_tech.json"),
		htmlFindingsFile:   filepath.Join(resultsPath, "html_findings.txt"),
		fuzzWordlist:       config.Cfg.Wordlists.Fuzzing,
		tempDir:            tempDir,
		errorLogger:        errorLogger,
	}
	
	if len(initialSubdomains) > 0 {
		if err := utils.CombineAndDeduplicateFiles(state.subdomainsFile, state.subdomainsFile, strings.Join(initialSubdomains, "\n")); err != nil {
			return "", nil, false, fmt.Errorf("failed to write initial subdomains: %w", err)
		}
	}

	if utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		input, err := os.ReadFile(state.subdomainsFile)
		if err != nil {
			return "", nil, false, fmt.Errorf("failed to read initial subdomains file: %w", err)
		}
		err = os.WriteFile(state.reconTargetsFile, input, 0644)
		if err != nil {
			return "", nil, false, fmt.Errorf("failed to initialize unified recon targets: %w", err)
		}
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	workflow := map[string]reconStep{
		"passiveenum":  stepRunPassiveEnum,
		"resolvedns":   stepRunResolveDNS,
		"portscan":     stepRunPortScan,
		"httpx":        stepRunHttpx,
		"enrich":       stepRunEnrichment,
		"fuzz":         stepRunFuzzing,
	}
	
	state.logger.Info("--- INICIANDO FASE 1: Descoberta Passiva de Subdomínios ---")
	var wgPhase1 sync.WaitGroup
	phase1Steps := []string{"passiveenum"}

	for _, stepName := range phase1Steps {
		if _, skip := skipSet[stepName]; skip {
			state.logger.Warn("Skipping step as requested by flags", "step", stepName)
			continue
		}
		wgPhase1.Add(1)
		go func(name string) {
			defer wgPhase1.Done()
			if err := workflow[name](state); err != nil {
				state.logger.Error("A reconnaissance step failed in Phase 1", "step", name, "error", err)
				state.errorLogger.Error("Recon Step Failed", "step", name, "error", err.Error())
			}
		}(stepName)
	}
	wgPhase1.Wait()
	state.logger.Info("--- FASE 1 CONCLUÍDA ---")

	state.logger.Info("--- INICIANDO FASE 2: Resolução e Varredura de Portas ---")
	if err := stepRunResolveDNS(state); err != nil {
		return "", nil, false, fmt.Errorf("critical step 'resolvedns' failed: %w", err)
	}
	if err := stepRunPortScan(state); err != nil {
		state.logger.Error("Port scanning failed, but continuing...", "error", err)
	}
	state.logger.Info("--- FASE 2 CONCLUÍDA ---")

	state.logger.Info("--- INICIANDO FASE 3: Identificação de Hosts Ativos ---")
	if err := stepRunHttpx(state); err != nil {
		state.logger.Warn("Httpx step finished with an error. This might be expected.", "error", err)
	}
	state.logger.Info("--- FASE 3 CONCLUÍDA ---")

	if !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) && utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Info("Nenhum host web ativo encontrado. Ativando fallback para usar subdomínios resolvidos nas próximas etapas.")
		if err := utils.CopyFile(state.subdomainsFile, state.liveSubdomainsFile); err != nil {
			state.logger.Error("Falha ao copiar subdomínios resolvidos para o arquivo de hosts vivos durante o fallback.", "error", err)
		}
	}

	state.logger.Info("--- INICIANDO FASE 4: Enumeração Web Ativa (Katana) ---")
	if _, skip := skipSet["webenum"]; !skip {
		if err := stepRunWebEnum(state); err != nil {
		state.logger.Error("A etapa de enumeração web (webenum) falhou, mas o fluxo continuará.", "error", err)
		state.errorLogger.Error("Recon Step Failed", "step", "webenum", "error", err.Error())
		}
	}
	state.logger.Info("--- FASE 4 CONCLUÍDA ---")

	if skipAnalysis {
		state.logger.Warn("Skipping entire Phase 5 (Analysis, Enrichment, Detection) as requested by --skip-analysis flag.")
	} else {
		state.logger.Info("--- INICIANDO FASE 5: Análise de Conteúdo, Enriquecimento e Detecção ---")
		var wgPhase5 sync.WaitGroup
		phase5Steps := []string{"webanalysis", "detection", "enrich"}
		for _, stepName := range phase5Steps {
			if _, skip := skipSet[stepName]; skip {
				state.logger.Warn("Skipping step as requested by flags", "step", stepName)
				continue
			}
			wgPhase5.Add(1)
			go func(name string) {
				defer wgPhase5.Done()
				var err error
				switch name {
				case "webanalysis":
					err = stepRunWebAnalysis(state)
				case "detection":
					err = stepRunDetection(state)
				case "enrich":
					err = stepRunEnrichment(state)
				}
				if err != nil {
					state.logger.Error("A reconnaissance step failed in Phase 5", "step", name, "error", err)
					state.errorLogger.Error("Recon Step Failed", "step", name, "error", err.Error())
				}
			}(stepName)
		}
		wgPhase5.Wait()
		state.logger.Info("--- FASE 5 CONCLUÍDA ---")
	}

	state.logger.Info("--- INICIANDO FASE 6: Fuzzing ---")
	if _, skip := skipSet["fuzz"]; !skip {
		if err := stepRunFuzzing(state); err != nil {
			state.logger.Error("Fuzzing step failed", "error", err)
			state.errorLogger.Error("Recon Step Failed", "step", "fuzz", "error", err.Error())
		}
	}
	state.logger.Info("--- FASE 6 CONCLUÍDA ---")

	slog.Info("Reconnaissance process completed.")
	jsFindings, err := analysis.ParseURLFindings(state.jsFindingsFile, state.logger)
	if err != nil {
		state.logger.Warn("Failed to parse JS findings for summary", "error", err)
	}
	state.parsedJSFindings = jsFindings
	htmlFindings, err := analysis.ParseURLFindings(state.htmlFindingsFile, state.logger)
	if err != nil {
		state.logger.Warn("Failed to parse HTML findings for summary", "error", err)
	}
	state.parsedHTMLFindings = htmlFindings

	if useResolvedForScan && !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) && utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Info("No live hosts found, but 'useResolvedForScan' is enabled. Proceeding with resolved subdomains for scanning.")
		if err := utils.CopyFile(state.subdomainsFile, state.liveSubdomainsFile); err != nil {
			state.logger.Error("Failed to copy resolved subdomains to live subdomains file for forced scan", "error", err)
		}
	}

	finalReconTargetsPath := filepath.Join(state.resultsPath, "recon_targets.txt")
	if utils.FileExistsAndIsNotEmpty(state.reconTargetsFile) {
		state.logger.Info("Moving unified recon targets file to main results directory.", "from", state.reconTargetsFile, "to", finalReconTargetsPath)
		if err := os.Rename(state.reconTargetsFile, finalReconTargetsPath); err != nil {
			state.logger.Warn("Failed to move unified recon targets file.", "error", err)
		} else {
			state.reconTargetsFile = finalReconTargetsPath
		}
	}

	liveHostsFound := utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile)
	summary, files, err := generateReconSummary(state)
	if err != nil {
		return "", nil, false, err
	}
	return summary, files, liveHostsFound, nil
}

func stepRunPassiveEnum(state *reconState) error {
	state.logger.Info("--- Starting: Aggregated Passive Subdomain Enumeration ---")

	var wg sync.WaitGroup
	var mu sync.Mutex
	allSubdomains := make(map[string]struct{})

	toolsToRun := map[string]func(context.Context, string, string, *slog.Logger) (string, error){
		"subfinder":   tools.RunSubfinder,
		"amass":       tools.RunAmass,
		"assetfinder": tools.RunAssetfinder,
		"sublist3r":   tools.RunSublist3r,
	}

	for name, runFunc := range toolsToRun {
		wg.Add(1)
		go func(toolName string, rf func(context.Context, string, string, *slog.Logger) (string, error)) {
			defer wg.Done()
			state.logger.Info("Starting passive tool", "tool", toolName)
			output, err := rf(state.ctx, state.target, state.tempDir, state.logger)
			if err != nil {
				state.logger.Warn("Passive enumeration tool finished with an error, but proceeding.", "tool", toolName, "error", err)
			}

			if output != "" {
				mu.Lock()
				scanner := bufio.NewScanner(strings.NewReader(output))
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line != "" {
						allSubdomains[line] = struct{}{}
					}
				}
				mu.Unlock()
			}
		}(name, runFunc)
	}

	wg.Wait()
	state.logger.Info("All passive enumeration tools have finished execution. Consolidating results...")

	if err := utils.WriteLines(state.subdomainsFile, allSubdomains); err != nil {
		state.logger.Error("Failed to consolidate passive enumeration results", "error", err)
		return err
	}

	if !utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Warn("No subdomains found during passive enumeration. Proceeding with the root target only.", "target", state.target)
		err := os.WriteFile(state.subdomainsFile, []byte(state.target+"\n"), 0644)
		if err != nil {
			state.logger.Error("Failed to write root target to subdomains file as a fallback.", "error", err)
			return fmt.Errorf("no subdomains found and failed to write fallback target: %w", err)
		}
	}

	state.logger.Info("Passive Subdomain Enumeration completed and consolidated.", "output_file", state.subdomainsFile, "total_unique_found", utils.CountLines(state.subdomainsFile))
	return nil
}

func stepRunEnrichment(state *reconState) error {
	state.logger.Info("--- Starting: External URL Enrichment Phase ---")
	steps := map[string]reconStep{
		"csp":     stepGetCSPDomains,
		"sitemap": stepGetSitemapURLs,
		"wayback": stepGetWaybackURLs,
	}
	for name, stepFunc := range steps {
		if err := stepFunc(state); err != nil {
			state.logger.Warn("Enrichment step failed but continuing.", "sub_step", name, "error", err)
		}
	}
	state.logger.Info("External URL Enrichment Phase completed.")
	return nil
}

func stepRunWebEnum(state *reconState) error {
	state.logger.Info("--- Starting: Active Web Enumeration Phase ---")
	if err := stepRunKatana(state); err != nil {
		state.logger.Error("Active web enumeration (katana) failed.", "error", err)
		return err
	}
	state.logger.Info("Active Web Enumeration Phase completed.")
	return nil
}

func stepRunWebAnalysis(state *reconState) error {
	state.logger.Info("--- Starting: Web Content Analysis Phase ---")
	steps := map[string]reconStep{
		"htmlanalysis": stepRunHTMLAnalysis,
		"jsanalysis":   stepRunJSAnalysis,
		"favicon":      stepRunFaviconHash,
	}
	for name, stepFunc := range steps {
		if err := stepFunc(state); err != nil {
			state.logger.Warn("Web analysis step failed but continuing.", "sub_step", name, "error", err)
		}
	}
	state.logger.Info("Web Content Analysis Phase completed.")
	return nil
}

func stepRunDetection(state *reconState) error {
	state.logger.Info("--- Starting: CVE Search and WAF Detection Phase ---")
	var wg sync.WaitGroup

	steps := map[string]reconStep{
		"cvesearch": stepRunCVESearch,
		"waf":       stepRunWafw00f,
	}

	for name, stepFunc := range steps {
		wg.Add(1)
		go func(stepName string, sf reconStep) {
			defer wg.Done()
			if err := sf(state); err != nil {
				state.logger.Warn("Detection step failed but continuing.", "sub_step", stepName, "error", err)
			}
		}(name, stepFunc)
	}
	wg.Wait()
	state.logger.Info("CVE Search and WAF Detection Phase completed.")
	return nil
}

func stepRunFaviconHash(state *reconState) error {
	state.logger.Info("--- Starting: Favicon Hash Analysis ---")
	faviconOutputFile := filepath.Join(state.resultsPath, "favicon_hashes.json")
	err := runFaviconHash(state.ctx, state.liveSubdomainsFile, faviconOutputFile, state.logger)
	if err != nil {
		return err
	}
	if utils.FileExistsAndIsNotEmpty(faviconOutputFile) {
		parsedHashes, err := parseFaviconHashes(faviconOutputFile, state.logger)
		if err != nil {
			state.logger.Warn("Failed to parse favicon hashes for summary", "error", err)
		}
		state.parsedFaviconHashes = parsedHashes
		state.logger.Info("Favicon analysis completed", "output_file", faviconOutputFile)
	}
	return nil
}

func stepRunHttpx(state *reconState) error {
	if !utils.CommandExists("httpx") {
		state.logger.Error("httpx is not installed or not executable. Please check your PATH and permissions.", "tool", "httpx")
		return fmt.Errorf("httpx not found or not executable")
	}
	state.logger.Info("--- Starting: Live Host Validation & Tech Analysis (httpx) ---")

	inputFile := state.reconTargetsFile
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		state.logger.Warn("Unified recon targets file is empty. Falling back to resolved subdomains for httpx.", "file", inputFile)
		inputFile = state.subdomainsFile
	}

	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		state.logger.Error("No valid input targets found for httpx after fallback. Skipping.", "file", inputFile)
		return nil
	}

	state.logger.Info("Httpx - Etapa 1: Descobrindo hosts vivos...")
	if err := tools.RunHttpx(state.ctx, inputFile, "", state.liveSubdomainsFile, state.tempDir, state.followRedirects, "", false, state.logger); err != nil {
		state.logger.Warn("httpx command finished with a non-zero exit code. This is often expected if no live web hosts are found.", "error", err)
	}

	if utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Info("Httpx - Etapa 2: Detectando tecnologias nos hosts vivos...")
		if err := tools.RunHttpx(state.ctx, state.liveSubdomainsFile, state.techFile, "", state.tempDir, state.followRedirects, "", true, state.logger); err != nil {
			state.logger.Warn("Httpx (tech-detect) command finished with a non-zero exit code.", "error", err)
		}
	}

	return nil
}

func stepRunHTMLAnalysis(state *reconState) error {
	state.logger.Info("--- Starting: HTML Source Code Analysis ---")
	if !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Warn("Live subdomains file is empty, skipping HTML analysis.", "file", state.liveSubdomainsFile)
		return nil
	}
	if err := runHTMLAnalysis(state); err != nil {
		return err
	}
	if utils.FileExistsAndIsNotEmpty(state.htmlFindingsFile) {
		state.logger.Info("HTML analysis completed", "output_file", state.htmlFindingsFile)
	} else {
		state.logger.Info("HTML analysis completed with no new findings.")
	}
	return nil
}

func stepRunFuzzing(state *reconState) error {
	state.logger.Info("--- Starting: Parallel Directory and File Fuzzing ---")

	if !utils.FileExistsAndIsNotEmpty(state.fuzzWordlist) {
		state.logger.Warn("Fuzzing wordlist not configured or file not found, skipping entire fuzzing step.", "path", state.fuzzWordlist)
		return nil
	}

	hosts, err := utils.ReadLines(state.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for fuzzing: %w", err)
	}
	if len(hosts) == 0 {
		state.logger.Warn("Live subdomains file is empty, skipping entire fuzzing step.", "file", state.liveSubdomainsFile)
		return nil
	}

	var rateLimit int
	if config.Cfg.Engine.WAF.Enabled {
		profile := config.Cfg.Engine.WAF.DefaultProfile
		rateLimit = profile.RateLimit
		state.logger.Info("Applying default WAF rate limit for all fuzzing tools.", "rate_limit", rateLimit)
	}

	var hostWg sync.WaitGroup
	hostConcurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	var completedHosts atomic.Int32
	totalHosts := len(hosts)
	for _, host := range hosts {
		hostWg.Add(1)
		hostConcurrencyLimit <- struct{}{}

		go func(h string) {
			defer hostWg.Done()
			defer func() { <-hostConcurrencyLimit }()

			var toolWg sync.WaitGroup

			// Ffuf
			toolWg.Add(1)
			go func() {
				defer toolWg.Done()
				state.logger.Info("Running ffuf for host", "host", h)
				fuzzResultsDir := filepath.Join(state.resultsPath, "ffuf_results")
				_ = tools.RunFfuf(state.ctx, h, state.fuzzWordlist, fuzzResultsDir, rateLimit, state.logger)
			}()

			// Dirsearch
			toolWg.Add(1)
			go func() {
				defer toolWg.Done()
				state.logger.Info("Running dirsearch for host", "host", h)
				dirsearchOutputDir := filepath.Join(state.resultsPath, "dirsearch_results")
				_ = tools.RunDirsearch(state.ctx, h, state.fuzzWordlist, dirsearchOutputDir, rateLimit, state.logger)
			}()

			// Feroxbuster
			toolWg.Add(1)
			go func() {
				defer toolWg.Done()
				state.logger.Info("Running feroxbuster for host", "host", h)
				feroxbusterOutputDir := filepath.Join(state.resultsPath, "feroxbuster_results")
				_ = tools.RunFeroxbuster(state.ctx, h, state.fuzzWordlist, feroxbusterOutputDir, 0, state.logger)
			}()

			toolWg.Wait()
			progress := completedHosts.Add(1)
			state.logger.Info("Fuzzing completed for host", "host", h, "progress", fmt.Sprintf("%d/%d", progress, totalHosts))
		}(host)
	}

	hostWg.Wait()
	state.logger.Info("Parallel fuzzing step completed.")
	return nil
}

func parseFaviconHashes(filePath string, logger *slog.Logger) ([]types.FaviconResult, error) {
	if !utils.FileExistsAndIsNotEmpty(filePath) {
		return nil, nil
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read favicon hashes file: %w", err)
	}
	return unmarshalFaviconResults(data, logger)
}

func stepRunKatana(state *reconState) error {
	state.logger.Info("--- Starting: URL Collection (katana) ---")
	inputFile := state.liveSubdomainsFile
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		state.logger.Warn("Live subdomains file is empty, skipping Katana.", "file", inputFile)
		return nil
	}

	err := tools.RunKatana(state.ctx, inputFile, state.urlsFile, state.tempDir, state.logger)
	if err == nil && utils.FileExistsAndIsNotEmpty(state.urlsFile) {
		if err := utils.CombineAndDeduplicateFiles(state.reconTargetsFile, state.urlsFile); err != nil {
			state.logger.Warn("Failed to add katana URLs to unified targets", "error", err)
		}
		state.logger.Info("URL Collection completed", "output_file", state.urlsFile)
	}
	return err
}

func stepRunJSAnalysis(state *reconState) error {
	state.logger.Info("--- Starting: JavaScript Analysis ---")
	err := runJSAnalysis(state.ctx, state.urlsFile, state.jsFindingsFile, state.logger)
	if err == nil && utils.FileExistsAndIsNotEmpty(state.jsFindingsFile) {
		state.logger.Info("JavaScript Analysis completed", "output_file", state.jsFindingsFile)
	}
	return err
}


func stepGetWaybackURLs(state *reconState) error {
	state.logger.Info("--- Starting: Augmenting with Wayback Machine URLs ---")
	waybackURLs, err := getWaybackURLs(state.ctx, state.target, state.logger)
	if err != nil {
		state.logger.Warn("Failed to get URLs from Wayback Machine, but continuing...", "error", err)
		return nil
	}
	if len(waybackURLs) > 0 {
		tempWaybackFile, err := os.CreateTemp(state.tempDir, "wayback_urls_*.txt")
		if err != nil {
			return fmt.Errorf("failed to create temporary file for wayback urls: %w", err)
		}
		defer os.Remove(tempWaybackFile.Name())
		defer tempWaybackFile.Close()

		if _, err := tempWaybackFile.WriteString(strings.Join(waybackURLs, "\n")); err != nil {
			return fmt.Errorf("failed to write wayback urls to temp file: %w", err)
		}

		err = utils.CombineAndDeduplicateFiles(state.urlsFile, tempWaybackFile.Name())
		if err != nil {
			return fmt.Errorf("failed to combine Wayback URLs: %w", err)
		}
		if err := utils.CombineAndDeduplicateFiles(state.reconTargetsFile, tempWaybackFile.Name()); err != nil {
			state.logger.Warn("Failed to add wayback URLs to unified targets", "error", err)
		}
		state.logger.Info("Successfully added URLs from Wayback Machine", "count", len(waybackURLs))
	}
	return nil
}

func stepRunPortScan(state *reconState) error {
	state.logger.Info("--- Starting: Port Scanning (naabu) ---")
	portScanOutputFile := filepath.Join(state.resultsPath, "portscan_results.txt")

	inputFile := state.subdomainsFile
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		state.logger.Warn("Subdomains file is empty, skipping port scan.", "file", inputFile)
		return nil
	}

	hosts, err := utils.ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for port scan: %w", err)
	}
	hostnames := make(map[string]struct{})
	for _, h := range hosts {
		if u, err := url.Parse(h); err == nil && u.Hostname() != "" {
			hostnames[u.Hostname()] = struct{}{}
		} else if !strings.Contains(h, "/") {
			hostnames[h] = struct{}{}
		}
	}

	tempInputFile, err := utils.WriteTempLines(hostnames, state.tempDir, "naabu_hosts_*.txt")
	if err != nil {
		return err
	}
	defer os.Remove(tempInputFile)

	if err := tools.RunNaabu(state.ctx, tempInputFile, portScanOutputFile, state.tempDir, state.logger); err != nil {
		return err
	}

	if utils.FileExistsAndIsNotEmpty(portScanOutputFile) {
		if err := utils.CombineAndDeduplicateFiles(state.reconTargetsFile, portScanOutputFile); err != nil {
		state.logger.Warn("Failed to add portscan results to unified targets", "error", err)
		}
	}
	state.logger.Info("Port scanning completed", "output_file", portScanOutputFile)
	return nil
}

func stepRunWafw00f(state *reconState) error {
	if !config.Cfg.Engine.WAF.Enabled {
		state.logger.Info("WAF detection is disabled in config, skipping.")
		return nil
	}
	state.logger.Info("--- Starting: WAF Detection (wafw00f) ---")
	wafOutputFile := filepath.Join(state.resultsPath, "waf_results.json")
	if !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Warn("Live subdomains file is empty, skipping WAF detection.", "file", state.liveSubdomainsFile)
		return nil
	}

	err := tools.RunWafw00f(state.ctx, state.liveSubdomainsFile, wafOutputFile, state.logger)
	if err != nil {
		return err
	}
	state.logger.Info("WAF detection completed", "output_file", wafOutputFile)
	return nil
}

func stepGetSitemapURLs(state *reconState) error {
	state.logger.Info("--- Starting: Sitemap URL Extraction ---")
	sitemapURLs, err := parseSitemap(state.ctx, state.target, state.logger)
	if err != nil {
		state.logger.Warn("Failed to get URLs from sitemap, but continuing...", "error", err)
		return nil
	}
	if len(sitemapURLs) > 0 {
		sitemapContent := strings.Join(sitemapURLs, "\n")
		if err := utils.CombineAndDeduplicateFiles(state.urlsFile, "", sitemapContent); err != nil {
			return fmt.Errorf("failed to combine sitemap URLs: %w", err)
		}
		if err := utils.CombineAndDeduplicateFiles(state.reconTargetsFile, "", sitemapContent); err != nil {
			state.logger.Warn("Failed to add sitemap URLs to unified targets", "error", err)
		}
		state.logger.Info("Successfully added URLs from sitemap", "count", len(sitemapURLs))
	}
	return nil
}

func stepGetCSPDomains(state *reconState) error {
	state.logger.Info("--- Starting: CSP Header Subdomain Extraction ---")
	cspDomains, err := getCSPDomains(state.ctx, state.liveSubdomainsFile, state.target, state.logger)
	if err != nil {
		state.logger.Warn("Failed to get subdomains from CSP headers, but continuing...", "error", err)
		return nil
	}
	if len(cspDomains) > 0 {
		state.logger.Info("Found new potential subdomains from CSP headers", "count", len(cspDomains))
		return utils.CombineAndDeduplicateFiles(state.subdomainsFile, "", strings.Join(cspDomains, "\n"))
	}
	state.logger.Info("CSP Header Subdomain Extraction completed with no new findings.")
	return nil
}

func getWaybackURLs(ctx context.Context, domain string, logger *slog.Logger) ([]string, error) { // This function needs logger too
	logger.Info("Fetching URLs from Wayback Machine", "domain", domain)
	apiURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)

	client := &http.Client{
		Timeout: 90 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}
	var resp *http.Response
	var err error
	maxRetries := 2

	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Wayback Machine request: %w", err)
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		resp, err = client.Do(req)
		if err == nil {
			break
		}
		logger.Warn("Wayback Machine request failed, retrying...", "attempt", i+1, "error", err)
		time.Sleep(2 * time.Second)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to fetch from Wayback Machine after %d retries: %w", maxRetries, err)
	}

	if resp == nil {
		return nil, fmt.Errorf("received nil response from Wayback Machine after retries")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		logger.Error("Wayback Machine returned non-200 status",
			"status_code", resp.StatusCode,
			"response_body", string(bodyBytes),
		)
		return nil, fmt.Errorf("wayback Machine returned non-200 status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read Wayback Machine response body: %w", err)
	}

	if len(body) == 0 {
		logger.Info("Wayback Machine returned an empty response", "domain", domain)
		return nil, nil
	}

	var results [][]string
	if err := json.Unmarshal(body, &results); err != nil {
		logger.Warn("Could not unmarshal Wayback Machine JSON response", "error", err, "response", string(body))
		return nil, nil
	}

	var urls []string
	if len(results) > 1 {
		for _, row := range results[1:] {
			if len(row) > 0 && row[0] != "" {
				urls = append(urls, row[0])
			}
		}
	}

	logger.Info("Found URLs in Wayback Machine", "count", len(urls), "domain", domain)
	return urls, nil
}

type SitemapIndex struct {
	Sitemaps []Sitemap `xml:"sitemap"`
}
type Sitemap struct {
	Loc string `xml:"loc"`
}
type URLSet struct {
	URLs []URL `xml:"url"`
}
type URL struct {
	Loc string `xml:"loc"`
}

func parseSitemap(ctx context.Context, domain string, logger *slog.Logger) ([]string, error) { // This function needs logger too
	logger.Info("Attempting to parse sitemap", "domain", domain)
	var foundURLs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	var processSitemapURL func(sitemapURL string)
	processSitemapURL = func(sitemapURL string) {
		defer wg.Done()
		req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
		if err != nil {
			logger.Warn("Failed to create sitemap request", "url", sitemapURL, "error", err)
			return
		}
		req.Header.Set("User-Agent", getRandomUserAgent())

		client := &http.Client{
			Timeout: 20 * time.Second,
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			logger.Warn("Failed to fetch sitemap", "url", sitemapURL, "error", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return // Silently ignore non-200, it's common for sitemaps not to exist
		}

		var reader io.Reader = resp.Body
		if strings.HasSuffix(sitemapURL, ".gz") {
			gzReader, err := gzip.NewReader(resp.Body)
			if err != nil {
				logger.Warn("Failed to create gzip reader for sitemap", "url", sitemapURL, "error", err)
				return
			}
			defer gzReader.Close()
			reader = gzReader
		}

		body, err := io.ReadAll(reader)
		if err != nil {
			logger.Warn("Failed to read sitemap body", "url", sitemapURL, "error", err)
			return
		}

		var sitemapIndex SitemapIndex
		if xml.Unmarshal(body, &sitemapIndex) == nil && len(sitemapIndex.Sitemaps) > 0 {
			for _, s := range sitemapIndex.Sitemaps {
				wg.Add(1)
				go processSitemapURL(s.Loc)
			}
			return
		}

		var urlSet URLSet
		if xml.Unmarshal(body, &urlSet) == nil && len(urlSet.URLs) > 0 {
			mu.Lock()
			for _, u := range urlSet.URLs {
				foundURLs = append(foundURLs, u.Loc)
			}
			mu.Unlock()
		}
	}

	initialSitemapURL := fmt.Sprintf("https://%s/sitemap.xml", domain)
	wg.Add(1)
	go processSitemapURL(initialSitemapURL)

	robotsURL := fmt.Sprintf("https://%s/robots.txt", domain)
	resp, err := http.Get(robotsURL)
	if err == nil && resp.StatusCode == http.StatusOK {
		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.ToLower(scanner.Text())
			if strings.HasPrefix(line, "sitemap:") {
				sitemapPath := strings.TrimSpace(strings.TrimPrefix(line, "sitemap:"))
				wg.Add(1)
				go processSitemapURL(sitemapPath)
			}
		}
		resp.Body.Close()
	}

	wg.Wait()
	logger.Info("Sitemap parsing finished", "urls_found", len(foundURLs))
	return foundURLs, nil
}

func IsMetadataTarget(urlStr string) bool {
	lowerURL := strings.ToLower(urlStr)
	extensions := []string{".pdf", ".jpg", ".jpeg", ".png", ".gif"}
	for _, ext := range extensions {
		if strings.HasSuffix(lowerURL, ext) {
			return true
		}
	}
	return false
}
func AnalyzeFileMetadata(ctx context.Context, wg *sync.WaitGroup, urlStr string, writer *bufio.Writer, mu *sync.Mutex, logger *slog.Logger) { // This function needs logger too
	defer wg.Done()
	logger.Debug("Analyzing file for metadata", "url", urlStr)

	req, err := http.NewRequestWithContext(ctx, "GET", urlStr, nil)
	if err != nil {
		logger.Error("Failed to create request for metadata analysis", "url", urlStr, "error", err)
		return
	}
	req.Header.Set("User-Agent", getRandomUserAgent())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logger.Error("Failed to download file for metadata analysis", "url", urlStr, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Warn("Failed to download file for metadata, non-200 status", "url", urlStr, "status", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read file body for metadata analysis", "url", urlStr, "error", err)
		return
	}
	reader := bytes.NewReader(body)

	var findings []string

		if strings.HasSuffix(strings.ToLower(urlStr), ".pdf") {
		if pdfReader, err := pdf.NewReader(reader, int64(reader.Len())); err == nil {
			infoDict := pdfReader.Trailer().Key("Info")
			if infoDict != (pdf.Value{}) {
				findings = append(findings, fmt.Sprintf("  - Type: PDF"))
				findings = append(findings, fmt.Sprintf("  - Pages: %d", pdfReader.NumPage()))


				if title := infoDict.Key("Title").Text(); title != "" {
					findings = append(findings, fmt.Sprintf("  - Title: %s", title))
				}
				if author := infoDict.Key("Author").Text(); author != "" {
					findings = append(findings, fmt.Sprintf("  - Author: %s", author))
				}
				if creator := infoDict.Key("Creator").Text(); creator != "" {
					findings = append(findings, fmt.Sprintf("  - Creator: %s", creator))
				}
				if producer := infoDict.Key("Producer").Text(); producer != "" {
					findings = append(findings, fmt.Sprintf("  - Producer: %s", producer))
				}
			}
		}
	}

	if _, err := reader.Seek(0, io.SeekStart); err == nil {
		if config, format, err := image.DecodeConfig(reader); err == nil {
			findings = append(findings, fmt.Sprintf("  - Type: Image (%s)", format))
			findings = append(findings, fmt.Sprintf("  - Dimensions: %dx%d", config.Width, config.Height))
		}
	}

	if strings.HasSuffix(strings.ToLower(urlStr), ".jpg") || strings.HasSuffix(strings.ToLower(urlStr), ".jpeg") {
		if _, err := reader.Seek(0, io.SeekStart); err == nil {
			if x, err := goexif.Decode(reader); err == nil {
				findings = append(findings, extractInterestingExif(x)...)
			}
		}
	}


	if len(findings) > 0 {
		mu.Lock()
		defer mu.Unlock()
		logger.Info("Found metadata in file", "url", urlStr)
		_, _ = writer.WriteString(fmt.Sprintf("[METADATA] File: %s\n", urlStr))
		for _, finding := range findings {
			_, _ = writer.WriteString(finding + "\n")
		}
		_, _ = writer.WriteString("\n")
	}
}

type exifWalker struct {
	findings []string
}


func (ew *exifWalker) Walk(name goexif.FieldName, tag *tiff.Tag) error {
	interestingFields := []goexif.FieldName{"Make", "Model", "Software", "DateTime", "GPSLatitude", "GPSLongitude"}
	for _, f := range interestingFields {
		if name == f {


			ew.findings = append(ew.findings, fmt.Sprintf("    - %s: %s", name, tag.String()))
		}
	}
	return nil
}

func extractInterestingExif(x *goexif.Exif) []string {
	walker := &exifWalker{}
	_ = x.Walk(walker)
	if len(walker.findings) > 0 {
		return append([]string{"  - EXIF Data:"}, walker.findings...)
	}
	return nil
}

func GetJSURLsFromFile(inputFile string) ([]string, error) { // This function needs logger too
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file %s: %w", inputFile, err)
	}
	defer file.Close()

	var jsURLs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, ".js?") || strings.HasSuffix(line, ".js") {
			if u, err := url.Parse(line); err == nil {
				u.RawQuery = ""
				u.Fragment = ""
				jsURLs = append(jsURLs, u.String())
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input file %s: %w", inputFile, err)
	}
	return jsURLs, nil
}

func DownloadContent(urlStr string) ([]byte, error) {
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request for %s: %w", urlStr, err)
	}
	req.Header.Set("User-Agent", getRandomUserAgent())

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to download from %s: %w", urlStr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 status code %d from %s", resp.StatusCode, urlStr)
	}

	return io.ReadAll(resp.Body)
}

func beautifyJS(jsContent string, urlStr string, logger *slog.Logger) string { // This function needs logger too
	cmd := exec.Command("jsbeautifier-go")
	cmd.Stdin = strings.NewReader(jsContent)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to run 'jsbeautifier-go'. Analyzing original content.", "url", urlStr, "error", err, "help", "Ensure 'jsbeautifier-go' is installed: go install github.com/ditashi/jsbeautifier-go@latest")
		return jsContent
	}
	return out.String()
}

func AnalyzeContentForPatterns(content string) (secrets []types.Finding, endpoints []types.Finding) {
	// Analisa segredos
	for _, pattern := range secretPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			matchCounts := make(map[string]int)
			for _, m := range matches {
				matchCounts[m]++
			}
			secrets = append(secrets, types.Finding{
				Pattern: pattern.String(),
				Matches: matchCounts,
			})
		}
	}

	for _, pattern := range endpointPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			matchCounts := make(map[string]int)
			for _, m := range matches {
				matchCounts[m]++
			}
			endpoints = append(endpoints, types.Finding{
				Pattern: pattern.String(),
				Matches: matchCounts,
			})
		}
	}
	return secrets, endpoints
}

func processSingleJSURL(ctx context.Context, jsURL string, writer *bufio.Writer, mu *sync.Mutex, logger *slog.Logger) { // This function needs logger too
	logger.Debug("Processing JS file", "url", jsURL)

	body, err := DownloadContent(jsURL)
	if err != nil {
		logger.Error("Failed to process JS file", "url", jsURL, "error", err)
		return
	}

	jsContent := string(body)
	beautifiedContent := beautifyJS(jsContent, jsURL, logger)

	jsSecrets, jsEndpoints := AnalyzeContentForPatterns(beautifiedContent)

	if len(jsSecrets) > 0 || len(jsEndpoints) > 0 {
		logger.Info("Found patterns in JS file", "url", jsURL)
		findings := types.URLFindings{
			URL:       jsURL,
			Secrets:   jsSecrets,
			Endpoints: jsEndpoints,
		}
		WriteFindings(writer, mu, "JS", findings, logger)
	}

	findAndAnalyzeSourcemap(jsURL, beautifiedContent, writer, mu, logger)
}

func WriteFindings(writer *bufio.Writer, mu *sync.Mutex, sourceType string, findings types.URLFindings, logger *slog.Logger) {
	mu.Lock()
	defer mu.Unlock()

	findings.SourceType = sourceType

	jsonData, err := json.Marshal(findings)
	if err != nil {
		logger.Error("Failed to marshal findings to JSON", "url", findings.URL, "error", err)
		return
	}

	_, _ = writer.WriteString(string(jsonData) + "\n")
}

func runJSAnalysis(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	logger.Info("Starting JavaScript analysis", "input", inputFile)
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for JS analysis does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	jsURLs, err := GetJSURLsFromFile(inputFile)
	if err != nil {
		return err
	}
	if len(jsURLs) == 0 {
		logger.Warn("No JavaScript URLs found in input file, skipping JS analysis.", "file", inputFile)
		return nil
	}

	uniqueURLs := make(map[string]struct{})
	for _, u := range jsURLs {
		uniqueURLs[u] = struct{}{}
	}

	deduplicatedURLs := make([]string, 0, len(uniqueURLs))
	for u := range uniqueURLs {
		deduplicatedURLs = append(deduplicatedURLs, u)
	}

	if len(jsURLs) > len(deduplicatedURLs) {
		logger.Info("Deduplicated JavaScript URLs for analysis.", "original_count", len(jsURLs), "unique_count", len(deduplicatedURLs))
	}


	output, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create js findings file %s: %w", outputFile, err)
	}
	defer output.Close()
	writer := bufio.NewWriter(output)
	defer writer.Flush()

	var wg sync.WaitGroup
	var muWriter sync.Mutex
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, jsURL := range deduplicatedURLs {
		select {
		case <-ctx.Done():
			logger.Info("JS analysis cancelled by context", "error", ctx.Err())
			return ctx.Err()
		case concurrencyLimit <- struct{}{}:
			wg.Add(1)
			go func(urlStr string) {
				defer wg.Done()
				defer func() { <-concurrencyLimit }()
				processSingleJSURL(ctx, urlStr, writer, &muWriter, logger)
			}(jsURL)
		}
	}
	wg.Wait()
	return nil
}

func findAndAnalyzeSourcemap(jsURL, jsContent string, writer *bufio.Writer, mu *sync.Mutex, logger *slog.Logger) { // This function needs logger too
	matches := sourceMappingURLRegex.FindStringSubmatch(jsContent)
	if len(matches) < 2 {
		return
	}

	sourceMapURL := strings.TrimSpace(matches[1])
	logger.Debug("Found sourcemap reference", "js_url", jsURL, "sourcemap_url", sourceMapURL)

	var sourceMapContent []byte
	var err error

	if strings.HasPrefix(sourceMapURL, "data:") {
		parts := strings.SplitN(sourceMapURL, ",", 2)
		if len(parts) == 2 && strings.Contains(parts[0], "base64") {
			sourceMapContent, err = base64.StdEncoding.DecodeString(parts[1])
		}
	} else {
		parsedJSURL, _ := url.Parse(jsURL)
		absoluteSourceMapURL := parsedJSURL.ResolveReference(&url.URL{Path: sourceMapURL}).String()
		logger.Debug("Downloading sourcemap", "url", absoluteSourceMapURL)
		sourceMapContent, err = DownloadContent(absoluteSourceMapURL)
	}

	if err != nil {
		logger.Warn("Failed to retrieve or decode sourcemap", "js_url", jsURL, "error", err)
		return
	}

	smSecrets, smEndpoints := analyzeSourceMap(jsURL, sourceMapContent, logger)

	if len(smSecrets) > 0 || len(smEndpoints) > 0 {
		logger.Info("Found patterns in sourcemap", "js_url", jsURL)
		findings := types.URLFindings{
			URL:       jsURL,
			Secrets:   smSecrets,
			Endpoints: smEndpoints,
		}
		WriteFindings(writer, mu, "SOURCEMAP", findings, logger)
	}
}

type SourceMap struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

func analyzeSourceMap(jsURL string, content []byte, logger *slog.Logger) (allSecrets []types.Finding, allEndpoints []types.Finding) { // This function needs logger too
	var sm SourceMap
	if err := json.Unmarshal(content, &sm); err != nil {
		logger.Warn("Failed to unmarshal sourcemap", "js_url", jsURL, "error", err)
		return nil, nil
	}

	if len(sm.SourcesContent) == 0 {
		return nil, nil
	}

	logger.Info("Analyzing content from sourcemap", "js_url", jsURL, "source_files", len(sm.SourcesContent))
	for _, sourceContent := range sm.SourcesContent {
		secrets, endpoints := AnalyzeContentForPatterns(sourceContent)
		if len(secrets) > 0 {
			allSecrets = append(allSecrets, secrets...)
		}
		if len(endpoints) > 0 {
			allEndpoints = append(allEndpoints, endpoints...)
		}
	}
	return allSecrets, allEndpoints
}

func runDnsx(ctx context.Context, subdomainsFile, tempDir string, logger *slog.Logger) ([]string, error) {
	resolversFile := filepath.Join(tempDir, "redrecon_resolvers.txt")

	if !utils.FileExistsAndIsNotEmpty(resolversFile) {
		logger.Warn("Resolvers file not found in temporary directory. Attempting to generate it...", "path", resolversFile)
		generateResolvers(resolversFile, logger)
	}

	if !utils.FileExistsAndIsNotEmpty(subdomainsFile) {
		logger.Warn("Input subdomains file is missing or empty, skipping dnsx.", "subdomains_file", subdomainsFile)
		return nil, nil
	}

	logger.Info("Executing external dnsx command for resolution.", "input_file", subdomainsFile)

	var args []string
	args = []string{
		"-l", subdomainsFile,
		"-resp",
		"-a",
		"-silent",
	}

	if utils.FileExistsAndIsNotEmpty(resolversFile) {
		args = append(args, "-r", resolversFile)
	}

	out, err := utils.ExecuteCommand(ctx, logger, "dnsx", args...)
	if err != nil {
		return nil, err
	}

	var foundSubdomains []string
	for _, line := range strings.Split(out, "\n") {
		if trimmedLine := strings.TrimSpace(line); trimmedLine != "" {
			foundSubdomains = append(foundSubdomains, strings.Fields(trimmedLine)[0])
		}
	}
	return foundSubdomains, nil
}

func generateResolvers(outputFile string, logger *slog.Logger) error {
	resolvers := []string{
		"1.1.1.1",         // Cloudflare
		"1.0.0.1",         // Cloudflare
		"8.8.8.8",         // Google
		"8.8.4.4",         // Google
		"9.9.9.9",         // Quad9
		"149.112.112.112", // Quad9
		"208.67.222.222",  // OpenDNS
		"208.67.220.220",  // OpenDNS
	}

	content := strings.Join(resolvers, "\n")
	err := os.WriteFile(outputFile, []byte(content), 0644)

	if err != nil {
		logger.Error("Failed to write built-in resolvers file. dnsx might use system resolvers.", "error", err)
		return err
	}
	logger.Info("Successfully created resolvers file from built-in list.", "path", outputFile)
	return nil
}

func stepRunResolveDNS(state *reconState) error {
	if !utils.CommandExists("dnsx") {
		state.logger.Error("dnsx is not installed or not executable. Please check your PATH and permissions.", "tool", "dnsx")
		return fmt.Errorf("dnsx not found or not executable")
	}
	state.logger.Info("--- Starting: Subdomain Resolution (dnsx) ---")

	resolversFile := filepath.Join(state.tempDir, "resolvers.txt")
	if err := generateResolvers(resolversFile, state.logger); err != nil {
		state.logger.Warn("Could not generate resolvers file, dnsx will use system default resolvers.", "error", err)
	}

	resolvedSubdomains, err := runDnsx(state.ctx, state.subdomainsFile, state.tempDir, state.logger)
	if err != nil {
		state.logger.Error("dnsx execution failed. Aborting recon.", "error", err)
		return fmt.Errorf("subdomain resolution with dnsx failed: %w", err)
	}

	if len(resolvedSubdomains) > 0 {
		resolvedContent := strings.Join(resolvedSubdomains, "\n")
		err = os.WriteFile(state.subdomainsFile, []byte(resolvedContent), 0644)
		if err != nil {
			return fmt.Errorf("failed to write resolved subdomains to file: %w", err)
		}

		normalizedURLs := normalizeDomainsToURLs(resolvedSubdomains)

		var normalizedContent strings.Builder
		for _, u := range normalizedURLs { // Correção: 'u' agora recebe o valor do elemento (string)
			normalizedContent.WriteString(u + "\n")
		}

		// Adiciona as URLs normalizadas ao arquivo de alvos do recon.
		if err := utils.CombineAndDeduplicateFiles(state.reconTargetsFile, normalizedContent.String()); err != nil {
			state.logger.Warn("Falha ao atualizar alvos unificados com subdomínios normalizados.", "error", err)
		}
	}

	state.logger.Info("Resolução de subdomínios concluída e URLs normalizadas.", "resolved_count", len(resolvedSubdomains))
	return nil
}

func normalizeDomainsToURLs(domains []string) []string {
	uniqueURLs := make(map[string]struct{})
	for _, domain := range domains {
		if domain != "" {
			uniqueURLs["http://"+domain] = struct{}{}
			uniqueURLs["https://"+domain] = struct{}{}
		}
	}
	
	var result []string
	for u := range uniqueURLs {
		result = append(result, u)
	}
	return result
}

func runFaviconHash(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for favicon analysis does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	
	hosts, err := utils.ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for favicon analysis: %w", err)
	}

	var allResults []types.FaviconResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	for _, host := range hosts {
		wg.Add(1)
		concurrencyLimit <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			faviconURLs, err := findFaviconURLs(ctx, h, logger)
			if err != nil {
				logger.Warn("Failed to find favicon URLs", "host", h, "error", err)
				return
			}
			faviconURL := faviconURLs[0]

			req, err := http.NewRequestWithContext(ctx, "GET", faviconURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", getRandomUserAgent())

			resp, err := client.Do(req)
			if err != nil || resp.StatusCode != http.StatusOK {
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return
			}

			hasher := murmur3.New32()
			_, _ = hasher.Write([]byte("\n"))
			_, _ = hasher.Write(body)
			hashValue := fmt.Sprintf("%d", int32(hasher.Sum32()))

			result := types.FaviconResult{
				Host:         h,
				FaviconURL:   faviconURL,
				Murmur3Hash:  hashValue,
				ShodanSearch: fmt.Sprintf("https://www.shodan.io/search?query=http.favicon.hash%%3A%s", hashValue),
			}

			mu.Lock()
			allResults = append(allResults, result)
			mu.Unlock()
		}(host)
	}

	wg.Wait()

	if len(allResults) > 0 {
		fileData, err := json.MarshalIndent(allResults, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal favicon results: %w", err)
		}
		return os.WriteFile(outputFile, fileData, 0644)
	}

	return nil
}

func findFaviconURLs(ctx context.Context, hostURL string, logger *slog.Logger) ([]string, error) {
	var foundURLs []string

	defaultFaviconURL, err := url.Parse(hostURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse host URL for favicon: %w", err)
	}
	defaultFaviconURL.Path = "/favicon.ico"
	foundURLs = append(foundURLs, defaultFaviconURL.String())

	c := colly.NewCollector(
		colly.MaxDepth(1),
		colly.Async(true),
	)
	c.SetClient(&http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	})

	c.OnHTML("link[rel~='icon']", func(e *colly.HTMLElement) {
		href := e.Attr("href")
		absoluteURL := e.Request.AbsoluteURL(href)
		foundURLs = append(foundURLs, absoluteURL)
	})

	c.OnRequest(func(r *colly.Request) {
		r.Headers.Set("User-Agent", getRandomUserAgent())
	})

	if err := c.Visit(hostURL); err != nil {
		return nil, err
	}
	c.Wait()

	return foundURLs, nil
}

func RunCVESearch(ctx context.Context, techFile, outputFile string, logger *slog.Logger) error {
	if !utils.FileExistsAndIsNotEmpty(techFile) {
		logger.Warn("Technology detection file does not exist or is empty, skipping CVE search.", "file", techFile)
		return nil
	}
	
	file, err := os.Open(techFile)
	if err != nil {
		return fmt.Errorf("failed to open tech file: %w", err)
	}
	defer file.Close()

	techMap := make(map[string][]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var info types.HttpxTechInfo
		if err := json.Unmarshal(scanner.Bytes(), &info); err == nil {
			for _, tech := range info.Tech {
				techMap[tech] = append(techMap[tech], info.URL)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading tech file: %w", err)
	}

	if len(techMap) == 0 {
		logger.Info("No technologies detected, skipping CVE search.")
		return nil
	}

	var allResults []types.CVEResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}

	for tech, urls := range techMap {
		wg.Add(1)
		go func(t string, u []string) {
			defer wg.Done()
			logger.Debug("Searching CVEs for technology", "tech", t)

			time.Sleep(1 * time.Second)

			apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&keywordExactMatch", url.QueryEscape(t))
			req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", getRandomUserAgent())

			resp, err := client.Do(req)
			if err != nil {
				logger.Warn("Failed to query NVD API", "tech", t, "error", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				logger.Warn("NVD API returned non-200 status", "tech", t, "status", resp.StatusCode)
				return
			}

			var nvdResp struct {
				Vulnerabilities []struct {
					CVE struct {
						ID           string `json:"id"`
						Descriptions []struct {
							Lang  string `json:"lang"`
							Value string `json:"value"`
						} `json:"descriptions"`
						Metrics struct {
							CVSSMetricV31 []struct {
								CVSSData struct {
									BaseScore    float64 `json:"baseScore"`
									BaseSeverity string  `json:"baseSeverity"`
								} `json:"cvssData"`
							} `json:"cvssMetricV31"`
						} `json:"metrics"`
					} `json:"cve"`
				} `json:"vulnerabilities"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
				logger.Warn("Failed to decode NVD API response", "tech", t, "error", err)
				return
			}

			mu.Lock()
			for _, vuln := range nvdResp.Vulnerabilities {
				result := types.CVEResult{
					URL:        strings.Join(u, ", "),
					Technology: t,
					CVE_ID:     vuln.CVE.ID,
				}
				if len(vuln.CVE.Descriptions) > 0 {
					result.Description = vuln.CVE.Descriptions[0].Value
				}
				if len(vuln.CVE.Metrics.CVSSMetricV31) > 0 {
					result.Severity = vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
					result.CVSS_V3 = fmt.Sprintf("%.1f", vuln.CVE.Metrics.CVSSMetricV31[0].CVSSData.BaseScore)
				}
				allResults = append(allResults, result)
			}
			mu.Unlock()
		}(tech, urls)
	}

	wg.Wait()

	if len(allResults) > 0 {
		fileData, err := json.MarshalIndent(allResults, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal CVE results: %w", err)
		}
		return os.WriteFile(outputFile, fileData, 0644)
	}

	return nil
}

func unmarshalFaviconResults(data []byte, logger *slog.Logger) ([]types.FaviconResult, error) {
	var results []types.FaviconResult
	if err := json.Unmarshal(data, &results); err != nil {
		logger.Warn("Failed to unmarshal favicon results JSON", "error", err)
		return nil, err
	}
	return results, nil
}

func runDirsearch(ctx context.Context, inputFile, wordlist, outputDir string, rateLimit int, logger *slog.Logger) error {
	if !utils.CommandExists("dirsearch") {
		logger.Warn("dirsearch is not installed or not executable, skipping.", "tool", "dirsearch", "help", "Install with: pip3 install dirsearch") // This function needs logger too
		return nil // Não é um erro fatal, apenas pula a ferramenta.
	}
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for dirsearch does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	if wordlist == "" || !utils.FileExistsAndIsNotEmpty(wordlist) {
		logger.Warn("Fuzzing wordlist not configured or file not found, skipping dirsearch.", "file", wordlist)
		return nil
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create dirsearch output directory: %w", err)
	}

	hosts, err := utils.ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for dirsearch: %w", err)
	}

	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, host := range hosts {
		wg.Add(1)
		concurrencyLimit <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			sanitizedHost := utils.SanitizeTargetForPath(h)
			hostOutputFile := filepath.Join(outputDir, sanitizedHost)

			logger.Debug("Running dirsearch scan", "host", h)
			args := []string{
				"-u", h,
				"-w", wordlist,
				"--output=" + hostOutputFile, // Formato do dirsearch
				"--format=json",
				"--force-recursive",
				"--random-user-agents",
			}

			if rateLimit > 0 {
				logger.Info("Applying rate limit to dirsearch.", "host", h, "rate", rateLimit)
				args = append(args, fmt.Sprintf("--rate=%d", rateLimit))
			}

			if _, err := utils.ExecuteCommand(ctx, logger, "dirsearch", args...); err != nil {
				logger.Warn("dirsearch scan for host failed", "host", h, "error", err)
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func getCSPDomains(ctx context.Context, liveSubdomainsFile, mainTarget string, logger *slog.Logger) ([]string, error) { // This function needs logger too
	if !utils.FileExistsAndIsNotEmpty(liveSubdomainsFile) {
		logger.Warn("Live subdomains file for CSP analysis does not exist or is empty, skipping.", "file", liveSubdomainsFile)
		return nil, nil
	}
	
	file, err := os.Open(liveSubdomainsFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open live subdomains file: %w", err)
	}
	defer file.Close()

	foundDomains := make(map[string]struct{})
	var mu sync.Mutex
	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
		},
	}
	domainRegex := regexp.MustCompile(`([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.)+[a-zA-Z]{2,}`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urlStr := scanner.Text()
		if urlStr == "" {
			continue
		}

		wg.Add(1)
		concurrencyLimit <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			req, err := http.NewRequestWithContext(ctx, "HEAD", u, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", getRandomUserAgent())

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			cspHeader := resp.Header.Get("Content-Security-Policy")
			if cspHeader == "" {
				return
			}

			matches := domainRegex.FindAllString(cspHeader, -1)
			if len(matches) > 0 {
				mu.Lock()
				for _, match := range matches {
					if strings.HasSuffix(match, "."+mainTarget) || match == mainTarget {
						foundDomains[match] = struct{}{}
					}
				}
				mu.Unlock()
			}
		}(urlStr)
	}

	wg.Wait()

	var result []string
	for domain := range foundDomains {
		result = append(result, domain)
	}

	return result, scanner.Err()
}

func stepRunCVESearch(state *reconState) error {
	state.logger.Info("--- Starting: Known CVE Search ---")
	cveOutputFile := filepath.Join(state.resultsPath, "cve_results.json")

	err := RunCVESearch(state.ctx, state.techFile, cveOutputFile, state.logger)
	if err != nil {
		state.logger.Error("CVE search step failed", "error", err)
	}
	state.logger.Info("CVE search completed.", "output_file", cveOutputFile)
	return nil
}

func runHTMLAnalysis(state *reconState) error {
	hosts, err := utils.ReadLines(state.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for HTML analysis: %w", err)
	}

	file, err := os.Create(state.htmlFindingsFile)
	if err != nil {
		return fmt.Errorf("failed to create HTML findings file: %w", err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()
	var mu sync.Mutex

	htmlFilesPath := filepath.Join(state.resultsPath, "html_files")
	if err := os.MkdirAll(htmlFilesPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory for HTML files: %w", err)
	}

	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(1),
	)

	_ = c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: config.Cfg.Engine.MaxParallelTasks,
		Delay:       50 * time.Millisecond,
	})

	c.OnRequest(func(r *colly.Request) {
		r.Headers.Set("User-Agent", getRandomUserAgent())
	})

	c.OnResponse(func(r *colly.Response) {
		htmlContent := string(r.Body)
		secrets, endpoints := AnalyzeContentForPatterns(htmlContent)

		if len(secrets) > 0 || len(endpoints) > 0 {
			findings := types.URLFindings{
				URL:       r.Request.URL.String(),
				Secrets:   secrets,
				Endpoints: endpoints,
			}
			WriteFindings(writer, &mu, "HTML", findings, state.logger)
		}
	})
	for _, host := range hosts {
		_ = c.Visit(host)
	}
	c.Wait()

	return nil
}

func generateReconSummary(state *reconState) (string, []string, error) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **Recon Summary for: %s**\n\n", state.target))

	summary.WriteString(fmt.Sprintf("• **Subdomains Found:** %d\n", utils.CountLines(state.subdomainsFile)))
	summary.WriteString(fmt.Sprintf("• **Live Hosts:** %d\n", utils.CountLines(state.liveSubdomainsFile)))
	summary.WriteString(fmt.Sprintf("• **URLs Discovered:** %d\n", utils.CountLines(state.urlsFile)))

	jsSecretCount := 0
	jsEndpointCount := 0
	for _, f := range state.parsedJSFindings {
		jsSecretCount += len(f.Secrets)
		jsEndpointCount += len(f.Endpoints)
	}
	if jsSecretCount > 0 || jsEndpointCount > 0 {
		summary.WriteString(fmt.Sprintf("• **JavaScript Analysis:** Found %d potential secrets and %d endpoints.\n", jsSecretCount, jsEndpointCount))
	}

	htmlSecretCount := 0
	htmlEndpointCount := 0
	for _, f := range state.parsedHTMLFindings {
		htmlSecretCount += len(f.Secrets)
		htmlEndpointCount += len(f.Endpoints)
	}
	if htmlSecretCount > 0 || htmlEndpointCount > 0 {
		summary.WriteString(fmt.Sprintf("• **HTML Analysis:** Found %d potential secrets and %d endpoints.\n", htmlSecretCount, htmlEndpointCount))
	}

	if len(state.parsedFaviconHashes) > 0 {
		summary.WriteString(fmt.Sprintf("• **Favicon Hashes:** %d unique hashes found. Useful for Shodan searches.\n", len(state.parsedFaviconHashes)))
	}

	summary.WriteString(fmt.Sprintf("\n*Full results are saved in:* `%s`", state.resultsPath))

	resultFiles := []string{
		state.subdomainsFile, state.liveSubdomainsFile, state.urlsFile,
		state.jsFindingsFile, state.htmlFindingsFile, state.techFile,
		state.reconTargetsFile,
	}
	return summary.String(), resultFiles, nil
}
