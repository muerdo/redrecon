package recon

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"image"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"redrecon/internal/config"
	"redrecon/pkg/tools"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"

	goexif "github.com/rwcarlsen/goexif/exif"
	"github.com/rwcarlsen/goexif/tiff"
	"github.com/schollz/progressbar/v3"
	"gopkg.in/yaml.v2"

	"bytes"
	"encoding/xml"
	"redrecon/pkg/analysis"

	"github.com/gocolly/colly/v2"
	"rsc.io/pdf"

	_ "image/gif" // Register GIF decoder
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

func getRandomUserAgent() string {
	userAgents := config.Cfg.Evasion.UserAgents
	// Fallback para uma lista padrão se não houver nada na configuração
	if len(userAgents) == 0 {
		userAgents = []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
			"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
			"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/114.0",
		}
	}
	rand.New(rand.NewSource(time.Now().UnixNano()))
	return userAgents[rand.Intn(len(userAgents))]
}

// reconStep define a assinatura de uma função que representa uma etapa no fluxo de reconhecimento.
type reconStep func(state *reconState) error

type reconState struct {
	ctx                context.Context
	target             string
	resultsPath        string
	subdomainsFile     string
	followRedirects    bool
	liveSubdomainsFile string
	liveURLsFile       string
	urlsFile           string
	targetsFile        string // Arquivos de entrada/saída das etapas
	reconTargetsFile   string
	techFile           string
	htmlFindingsFile   string
	tempDir            string
	logger             *slog.Logger
	errorLogger        *slog.Logger
	parsedHTMLFindings []types.URLFindings // Findings da análise de HTML

	// Fields for BBOT
	bbotJSONFile      string
	bbotLiveHostsFile string
	bbotURLsFile      string
	bbotAPKsFile      string
	bbotDockerFile    string
	bbotExposedFile   string
	TechStack         []string          // Ex: ["wordpress", "cloudflare", "nginx"]
	TechFingerprint   map[string]string // Ex: {"cms": "wordpress", "waf": "cloudflare"}

	proxyManager *utils.ProxyManager
	limiter      *utils.ConcurrencyLimiter // Concurrency control
	headers      []string
	cookies      string
	username     string
	password     string

	// New fields
	downloadContent bool
	staticAnalysis  bool
	bbotPreset      string
	nucleiTags      string
}

// MarkPartialFail logs a warning that a step failed but execution continues
func (s *reconState) MarkPartialFail(step string, err error) {
	s.logger.Warn("Partial step failure (continuing)", "step", step, "error", err)
}

// ... existing helper functions ...

// StartRecon initiates the reconnaissance process
func StartRecon(ctx context.Context, taskIdentifier, rootTarget string, initialSubdomains []string, skipSteps []string, onlySteps []string, bbotPresets []string, bbotModules []string, skipAnalysis bool, followRedirects bool, resolveIP bool, forceScan bool, reconDownloadContent bool, reconStaticAnalysis bool, bbotPreset string, nucleiTags string, proxyManager *utils.ProxyManager, headers []string, cookies, username, password string, logger *slog.Logger, streamMode bool) (string, []string, bool, error) {
	slog.Info("Starting reconnaissance process", "target", rootTarget)

	// Create concurrency limiter based on config
	maxParallel := config.Cfg.Engine.MaxParallelTasks
	if maxParallel <= 0 {
		maxParallel = 2 // Safe default
	}
	// In CTF mode, this might be even lower (controlled by config overrides)
	limiter := utils.NewConcurrencyLimiter(maxParallel)
	logger.Info("Concurrency limiter initialized", "max_parallel", maxParallel)

	sanitizedTaskIdentifier := utils.SanitizeTargetForPath(taskIdentifier)
	resultsPath := filepath.Join("results", sanitizedTaskIdentifier)
	slog.Info("Creating output directory", "path", resultsPath)

	if err := os.MkdirAll(resultsPath, 0755); err != nil && !os.IsExist(err) {
		slog.Error("Failed to create directory", "path", resultsPath, "error", err)
		return "", nil, false, fmt.Errorf("could not create directory %s: %w", resultsPath, err)
	}

	// FIX: Ensure temp directory exists
	tempDir := filepath.Join(resultsPath, "recon", "tmp")
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
		subdomainsFile:     filepath.Join(resultsPath, "recon", "subdomains.txt"),
		liveSubdomainsFile: filepath.Join(resultsPath, "recon", "live_subdomains.txt"),
		liveURLsFile:       filepath.Join(resultsPath, "recon", "live_urls.txt"),
		urlsFile:           filepath.Join(resultsPath, "recon", "urls.txt"),
		targetsFile:        filepath.Join(resultsPath, "recon", "targets.txt"),
		reconTargetsFile:   filepath.Join(tempDir, "recon_targets.txt"),
		logger:             logger,
		techFile:           filepath.Join(resultsPath, "recon", "httpx_tech.json"),
		htmlFindingsFile:   filepath.Join(resultsPath, "recon", "html_findings.txt"),
		tempDir:            tempDir,
		errorLogger:        errorLogger,

		// Initialize BBOT output paths
		bbotJSONFile:      filepath.Join(resultsPath, "recon", "bbot.json"),
		bbotLiveHostsFile: filepath.Join(resultsPath, "recon", "live_subdomains.txt"),
		bbotURLsFile:      filepath.Join(resultsPath, "recon", "urls.txt"),
		bbotAPKsFile:      filepath.Join(resultsPath, "recon", "apk_files.txt"),
		bbotDockerFile:    filepath.Join(resultsPath, "recon", "docker_files.txt"),
		bbotExposedFile:   filepath.Join(resultsPath, "recon", "bbot_exposed.txt"),
	}
	state.proxyManager = proxyManager
	state.limiter = limiter // Assign limiter
	state.headers = headers
	state.cookies = cookies
	state.username = username
	state.password = password
	state.downloadContent = reconDownloadContent
	state.staticAnalysis = reconStaticAnalysis
	state.bbotPreset = bbotPreset
	state.nucleiTags = nucleiTags

	if len(initialSubdomains) > 0 {
		// Correção: Lógica mais segura para evitar que o nome do arquivo seja tratado como um alvo
		// 1. Escreve os alvos iniciais em um arquivo temporário.
		tempInitialSubsFile, err := os.CreateTemp(state.tempDir, "initial_subs_*.txt")
		if err != nil {
			return "", nil, false, fmt.Errorf("failed to create temporary file for initial subdomains: %w", err)
		}
		// defer os.Remove(tempInitialSubsFile.Name()) // Desativado para depuração

		if _, err := tempInitialSubsFile.WriteString(strings.Join(initialSubdomains, "\n")); err != nil {
			tempInitialSubsFile.Close()
			return "", nil, false, fmt.Errorf("failed to write initial subdomains to temp file: %w", err)
		}
		tempInitialSubsFile.Close()

		// 2. Combina o arquivo temporário com o arquivo de subdomínios existente (se houver).
		if err := utils.CombineAndDeduplicateFiles(state.subdomainsFile, state.subdomainsFile, tempInitialSubsFile.Name()); err != nil {
			return "", nil, false, fmt.Errorf("failed to combine initial subdomains: %w", err)
		}
		logger.Info("Initial subdomains processed and added.", "count", len(initialSubdomains))
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

	// STREAMING MODE CHECKPOINT
	if streamMode {
		if err := StartStreamingRecon(state); err != nil {
			return "", nil, false, err
		}
		// If streaming loop finishes (e.g. timeout or context cancel), we might return results?
		// For now, let's assume it runs until completion and we return empty summary as interactive logging handles it.
		return "Streaming Recon Completed/Interrupted", []string{}, true, nil
	}

	workflow := map[string]reconStep{
		"uncover":           stepRunUncover,
		"resolveip":         stepResolveTargetIP,
		"passiveenum":       stepRunPassiveEnum,
		"cleansubdomains":   stepCleanSubdomains,
		"resolvesubdomains": stepResolveSubdomainIPs,
		"bbot":              func(state *reconState) error { return stepRunBBot(state, bbotPresets, bbotModules) },
		"livehosts":         stepRunLiveHosts,
		"techdetect":        stepRunTechDetect,
		"webenum":           stepRunWebEnum,
		"webanalysis":       stepRunWebAnalysis,
		"enrich":            stepRunEnrichment,
		"detection":         stepRunDetection,
		"takeover":          stepRunSubdomainTakeover, // Assuming stepRunSubdomainTakeover exists
		"portscan":          stepRunPortScan,
		"mantra":            stepRunMantra,
		"trufflehog":        stepRunTruffleHog,

		"contentanalysis": stepRunContentAnalysis,
		"downloadcontent": stepDownloadSiteContent,
		"staticanalysis":  stepRunStaticAnalysis,
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	// Initialize progress bar
	// Estimated total steps: ~15-20 depending on flags.
	// We'll use a safe upper bound or dynamic count.
	// For simplicity, let's use -1 for an indeterminate spinner or a fixed number if we count.
	// Let's count enabled steps.
	totalSteps := 0
	if _, skip := skipSet["uncover"]; !skip {
		totalSteps++
	}
	if _, skip := skipSet["resolveip"]; !skip {
		totalSteps++
	}
	if _, skip := skipSet["passiveenum"]; !skip {
		totalSteps++
	}
	if _, skip := skipSet["cleansubdomains"]; !skip {
		totalSteps++
	}
	if _, skip := skipSet["resolvesubdomains"]; !skip {
		totalSteps++
	}
	if _, skip := skipSet["bbot"]; !skip {
		totalSteps++
	}
	if _, skip := skipSet["livehosts"]; !skip {
		totalSteps++
	}
	if _, skip := skipSet["techdetect"]; !skip {
		totalSteps++
	}

	// Web parallel steps
	webSteps := []string{"webenum", "webanalysis", "enrich", "detection", "takeover"}
	for _, s := range webSteps {
		if _, skip := skipSet[s]; !skip {
			totalSteps++
		}
	}

	// Infra parallel step
	if _, skip := skipSet["portscan"]; !skip {
		totalSteps++
	}

	if _, skip := skipSet["mantra"]; !skip {
		totalSteps++
	}
	if _, skip := skipSet["trufflehog"]; !skip {
		totalSteps++
	}
	if state.downloadContent {
		totalSteps++
	}
	if state.staticAnalysis {
		totalSteps++
	}
	if reconDownloadContent {
		totalSteps++
	} // downloadjs

	bar := progressbar.Default(int64(totalSteps), "Recon Progress")

	// Initialize StepRunner
	runner := utils.NewStepRunner(ctx, logger)
	runner.SetStatusCallback(func(stepName string) {
		bar.Describe(fmt.Sprintf("Running: %s", stepName))
	})
	runner.StartInputMonitor()   // Checkpoint: Enable interactive status
	state.ctx = runner.Context() // Update state context to be managed by runner

	// FASE 0: Resolução de IP do Alvo
	if _, skip := skipSet["uncover"]; !skip {
		err := runner.Run("Uncover", func(ctx context.Context) error {
			state.ctx = ctx
			return stepRunUncover(state)
		})
		if err != nil {
			state.logger.Warn("Uncover failed (non-fatal)", "error", err)
		}
		bar.Add(1)
	}

	if _, skip := skipSet["resolveip"]; !skip {
		err := runner.Run("Resolve IP", func(ctx context.Context) error {
			state.ctx = ctx
			return stepResolveTargetIP(state)
		})
		if err != nil {
			state.logger.Warn("IP resolution failed (non-fatal)", "error", err)
		}
		bar.Add(1)
	}

	// FASE 1: Enumeração Passiva de Subdomínios
	state.logger.Info("--- INICIANDO FASE 1: Enumeração Passiva de Subdomínios (Subfinder, Amass) ---")
	if _, skip := skipSet["passiveenum"]; !skip {
		err := runner.Run("Passive Enum", func(ctx context.Context) error {
			state.ctx = ctx
			return stepRunPassiveEnum(state)
		})
		if err != nil {
			// Um erro aqui não é fatal, podemos continuar com o alvo raiz.
			state.errorLogger.Error("Recon Step Failed (Non-Fatal)", "step", "passiveenum", "error", err.Error())
			state.logger.Warn("A enumeração passiva de subdomínios falhou, continuando com o alvo raiz.", "error", err)
		}
		bar.Add(1)
	}

	// Clean subdomains after passive enum
	if _, skip := skipSet["cleansubdomains"]; !skip {
		err := runner.Run("Clean Subdomains", func(ctx context.Context) error {
			state.ctx = ctx
			return stepCleanSubdomains(state)
		})
		if err != nil {
			state.logger.Warn("Subdomain cleaning failed (non-fatal)", "error", err)
		}
		bar.Add(1)
	}

	// FASE 2: Descoberta e Validação Abrangente com BBOT
	state.logger.Info("--- INICIANDO FASE 2: Descoberta e Validação com BBOT ---")
	if _, skip := skipSet["bbot"]; !skip {
		// Pass the preset from state if available, otherwise use the slice passed
		presets := bbotPresets
		if state.bbotPreset != "" {
			presets = append(presets, state.bbotPreset)
		}
		err := runner.Run("BBot", func(ctx context.Context) error {
			state.ctx = ctx
			return stepRunBBot(state, presets, bbotModules)
		})
		if err != nil {
			state.errorLogger.Error("Recon Step Failed (Critical)", "step", "bbot", "error", err.Error())
			// O erro de BBOT é crítico, pois alimenta o resto do fluxo
			return "", nil, false, fmt.Errorf("etapa crítica 'bbot' falhou: %w", err)
		}
		bar.Add(1)
	}

	// FASE 2.5: Validação de Hosts Vivos (fallback)
	if _, skip := skipSet["livehosts"]; !skip {
		if !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
			err := runner.Run("Live Hosts", func(ctx context.Context) error {
				state.ctx = ctx
				return stepRunLiveHosts(state)
			})
			if err != nil {
				state.errorLogger.Error("Recon Step Failed (Non-Fatal)", "step", "livehosts", "error", err.Error())
				state.logger.Warn("Live hosts detection failed.", "error", err)
			}
		}
		bar.Add(1)
	}

	// Resolve IPs for all subdomains (collected so far)
	if _, skip := skipSet["resolvesubdomains"]; !skip {
		err := runner.Run("Resolve Subdomains IPs", func(ctx context.Context) error {
			state.ctx = ctx
			return stepResolveSubdomainIPs(state)
		})
		if err != nil {
			state.logger.Warn("Subdomain IP resolution failed (non-fatal)", "error", err)
		}
		// bar.Add(1) // Assuming we added it to totalSteps? We need to add it.
	}

	state.logger.Info("--- FASES 1 & 2 CONCLUÍDAS ---")

	// FASE 3: Execução condicional baseada nos outputs do BBOT
	state.logger.Info("--- INICIANDO FASE 3: Análise e Enumeração Direcionada ---")
	var wg sync.WaitGroup

	// "Modo Web": Ativado se encontrarmos hosts web
	if utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Info("Hosts web detectados. Ativando fluxo de análise web.")

		// Run techdetect before other web steps
		if _, skip := skipSet["techdetect"]; !skip {
			err := runner.Run("Tech Detect", func(ctx context.Context) error {
				state.ctx = ctx
				return stepRunTechDetect(state)
			})
			if err != nil {
				state.errorLogger.Error("Recon Step Failed", "step", "techdetect", "error", err.Error())
				state.logger.Error("Tech detection step failed", "error", err)
			}
			bar.Add(1)
		}

		for _, stepName := range webSteps {
			if _, skip := skipSet[stepName]; !skip {
				wg.Add(1)
				go func(name string, stepFunc reconStep) {
					defer wg.Done()

					// Acquire concurrency slot
					if err := state.limiter.Acquire(state.ctx); err != nil {
						state.logger.Warn("Could not acquire concurrency slot", "step", name, "error", err)
						return
					}
					defer state.limiter.Release()

					if err := stepFunc(state); err != nil {
						state.logger.Error("A etapa de reconhecimento web falhou", "step", name, "error", err)
						state.errorLogger.Error("Recon Step Failed", "step", name, "error", err.Error())
					}
					bar.Add(1)
				}(stepName, workflow[stepName])
			}
		}
	} else {
		state.logger.Info("Nenhum host web detectado pelo BBOT. Pulando etapas de análise web.")
		// Increment bar for skipped web steps to keep total accurate?
		// Or just let it finish incomplete?
		// Better to not count them if we skip? But we counted them in totalSteps.
		// Let's just add them here to complete the bar.
		skippedCount := 0
		if _, skip := skipSet["techdetect"]; !skip {
			skippedCount++
		}
		for _, s := range webSteps {
			if _, skip := skipSet[s]; !skip {
				skippedCount++
			}
		}
		bar.Add(skippedCount)
	}

	// "Modo Infra": Ativado se encontrarmos subdomínios (mesmo que não sejam web)
	if _, skip := skipSet["portscan"]; !skip && utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Info("Subdomínios encontrados. Ativando fluxo de scan de infra (portscan).")
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Acquire concurrency slot
			if err := state.limiter.Acquire(state.ctx); err != nil {
				state.logger.Warn("Could not acquire concurrency slot for portscan", "error", err)
				return
			}
			defer state.limiter.Release()

			// Same for portscan, it's parallel to web steps.
			if err := stepRunPortScan(state); err != nil {
				state.logger.Error("A etapa de portscan falhou", "step", "portscan", "error", err)
				state.errorLogger.Error("Recon Step Failed", "step", "portscan", "error", err.Error())
			}
			bar.Add(1)
		}()
	} else if _, skip := skipSet["portscan"]; !skip {
		bar.Add(1) // Skipped due to no subdomains
	}

	wg.Wait()

	// FASE 4: Análise de segredos e conteúdo
	if _, skip := skipSet["mantra"]; !skip {
		err := runner.Run("Mantra", func(ctx context.Context) error {
			state.ctx = ctx
			return stepRunMantra(state)
		})
		if err != nil {
			state.logger.Error("Mantra step failed", "error", err)
		}
		bar.Add(1)
	}
	if _, skip := skipSet["trufflehog"]; !skip {
		err := runner.Run("TruffleHog", func(ctx context.Context) error {
			state.ctx = ctx
			return stepRunTruffleHog(state)
		})
		if err != nil {
			state.logger.Error("TruffleHog step failed", "error", err)
		}
		bar.Add(1)
	}

	state.logger.Info("--- FASES SUBSEQUENTES CONCLUÍDAS ---")

	if state.downloadContent {
		state.logger.Info("--- INICIANDO FASE ADICIONAL: Download de Conteúdo do Site ---")
		err := runner.Run("Download Content", func(ctx context.Context) error {
			state.ctx = ctx
			return stepDownloadSiteContent(state)
		})
		if err != nil {
			state.logger.Error("A etapa de download de conteúdo falhou, mas o fluxo continuará.", "error", err)
			state.errorLogger.Error("Recon Step Failed", "step", "downloadcontent", "error", err.Error())
		}
		bar.Add(1)
	}

	if state.staticAnalysis {
		state.logger.Info("--- INICIANDO FASE ADICIONAL: Análise Estática (Semgrep) ---")
		err := runner.Run("Static Analysis", func(ctx context.Context) error {
			state.ctx = ctx
			return stepRunStaticAnalysis(state)
		})
		if err != nil {
			state.logger.Error("A etapa de análise estática falhou, mas o fluxo continuará.", "error", err)
			state.errorLogger.Error("Recon Step Failed", "step", "staticanalysis", "error", err.Error())
		}
		bar.Add(1)
	}

	if reconDownloadContent {
		state.logger.Info("--- INICIANDO FASE ADICIONAL: Download de Conteúdo JS ---")
		err := runner.Run("Download JS", func(ctx context.Context) error {
			state.ctx = ctx
			return stepRunDownloadJSContent(state)
		})
		if err != nil {
			state.logger.Error("A etapa de download de conteúdo JS falhou, mas o fluxo continuará.", "error", err)
			state.errorLogger.Error("Recon Step Failed", "step", "downloadjs", "error", err.Error())
		}
		bar.Add(1)
	}

	if !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) && utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Info("Nenhum host web ativo encontrado. Ativando fallback para usar subdomínios resolvidos nas próximas etapas.")

		resolvedSubdomains, err := utils.ReadLines(state.subdomainsFile)
		if err != nil {
			state.logger.Error("Falha ao ler subdomínios resolvidos para o fallback.", "error", err)
		} else {
			normalizedURLs := normalizeDomainsToURLs(resolvedSubdomains)
			content := strings.Join(normalizedURLs, "\n")
			if err := os.WriteFile(state.liveSubdomainsFile, []byte(content), 0644); err != nil {
				state.logger.Error("Falha ao escrever URLs normalizadas no arquivo de hosts vivos durante o fallback.", "error", err)
			}
		}
	}
	slog.Info("Reconnaissance process completed.")
	// FIX: Pula a análise se o arquivo de resultados não existir ou estiver vazio.
	if utils.FileExistsAndIsNotEmpty(state.htmlFindingsFile) {
		htmlFindings, err := analysis.ParseURLFindings(state.htmlFindingsFile, state.logger)
		if err != nil {
			state.logger.Warn("Failed to parse HTML findings for summary", "error", err)
		}
		state.parsedHTMLFindings = htmlFindings
	}

	// Adiciona endpoints encontrados na análise HTML aos alvos de recon unificados
	if err := addEndpointsToReconTargets(state); err != nil {
		state.logger.Error("Failed to add HTML endpoints to recon targets", "error", err)
	}

	// Garante que todos os alvos coletados (subdomínios, urls, portas) sejam unificados.
	// A chamada agora inclui o próprio arquivo de destino como fonte para garantir que nada seja perdido.
	// FIX: Sanitize before combining to remove DNS info and file paths
	if err := utils.SanitizeAndCombineReconTargets(
		state.reconTargetsFile,
		state.reconTargetsFile,       // Inclui o conteúdo existente
		state.subdomainsFile,         // Adiciona conteúdo do arquivo de subdomínios
		state.urlsFile); err != nil { // Adiciona conteúdo do arquivo de URLs
		state.logger.Error("Failed to perform final consolidation of recon targets", "error", err)
	}

	if forceScan && !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) && utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Info("No live hosts found, but 'useResolvedForScan' is enabled. Proceeding with resolved subdomains for scanning.")
		if err := utils.CopyFile(state.subdomainsFile, state.liveSubdomainsFile); err != nil {
			state.logger.Error("Failed to copy resolved subdomains to live subdomains file for forced scan", "error", err)
		}
	}

	// O caminho final deve ser dentro do subdiretório 'recon' para manter a organização.
	finalReconTargetsPath := filepath.Join(state.resultsPath, "recon", "recon_targets.txt")
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

// stepRunProbing usa httpx para descobrir hosts web vivos e detectar tecnologias.
// Esta é uma etapa crucial que transforma uma lista de domínios em URLs acionáveis.
func stepRunProbing(state *reconState) error {
	if !utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Warn("Arquivo de subdomínios está vazio, pulando a sondagem com httpx.", "file", state.subdomainsFile)
		return nil
	}
	state.logger.Info("--- Iniciando: Sondagem de Hosts Vivos e Detecção de Tecnologia (httpx) ---")

	var proxy string
	if state.proxyManager != nil {
		proxy = state.proxyManager.GetNextProxy()
	}

	// Etapa 1: Descobrir hosts vivos e salvar em live_subdomains.txt
	state.logger.Info("Httpx - Etapa 1: Descobrindo hosts vivos...")
	err := tools.RunHttpx(state.ctx, state.subdomainsFile, "", state.liveSubdomainsFile, state.tempDir, state.followRedirects, "", false, proxy, state.headers, state.cookies, state.username, state.password, state.logger)
	if err != nil {
		// Um erro aqui pode ser normal se nenhum host for encontrado, então apenas registramos.
		state.logger.Warn("Sondagem com httpx para hosts vivos concluída com aviso.", "error", err)
	}

	// Etapa 2: Detectar tecnologias nos hosts vivos encontrados
	if utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Info("Httpx - Etapa 2: Detectando tecnologias nos hosts vivos...")
		err = tools.RunHttpx(state.ctx, state.liveSubdomainsFile, state.techFile, "", state.tempDir, state.followRedirects, "", true, proxy, state.headers, state.cookies, state.username, state.password, state.logger)
		if err != nil {
			state.logger.Warn("Detecção de tecnologia com httpx concluída com aviso.", "error", err)
		}
	}
	return nil // Esta etapa não é considerada crítica para falhar todo o fluxo.
}

// stepRunPassiveEnum executa ferramentas de enumeração passiva de subdomínios como subfinder e amass.
func stepRunPassiveEnum(state *reconState) error {
	state.logger.Info("--- Starting: Passive Subdomain Enumeration ---")

	var wg sync.WaitGroup
	mu := &sync.Mutex{}
	tempFiles := []string{}

	// Ferramentas a serem executadas em paralelo (bloqueantes para esta fase)
	passiveTools := []struct {
		name    string
		runner  func(context.Context, string, string, string, *slog.Logger) (string, error)
		enabled bool
	}{
		{"subfinder", tools.RunSubfinder, config.Cfg.Tools.Subfinder.Enabled},
		{"assetfinder", func(ctx context.Context, target, tempDir, proxy string, logger *slog.Logger) (string, error) {
			// Assetfinder doesn't support proxy natively, so we ignore it
			return tools.RunAssetfinder(ctx, target, tempDir, logger)
		}, config.Cfg.Tools.Assetfinder.Enabled},
	}

	// Executa Amass em background se habilitado
	if config.Cfg.Tools.Amass.Enabled {
		state.logger.Info("Starting Amass in background...")
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Acquire concurrency slot
			if err := state.limiter.Acquire(state.ctx); err != nil {
				state.logger.Warn("Could not acquire concurrency slot for Amass", "error", err)
				return
			}
			defer state.limiter.Release()

			// Check context before starting
			if state.ctx.Err() != nil {
				return
			}

			proxy := ""
			if state.proxyManager != nil {
				proxy = state.proxyManager.GetNextProxy()
			}
			outputFile, err := tools.RunAmass(state.ctx, state.target, state.tempDir, proxy, state.logger)
			if err != nil {
				state.MarkPartialFail("amass", err)
				return
			}

			if err := utils.CombineAndDeduplicateFiles(state.subdomainsFile, state.subdomainsFile, outputFile); err != nil {
				state.logger.Error("Failed to merge Amass results", "error", err)
			} else {
				state.logger.Info("Amass results merged successfully", "file", outputFile)
			}
		}()
	}

	for _, tool := range passiveTools {
		if !tool.enabled {
			state.logger.Info("Skipping disabled passive tool", "tool", tool.name)
			continue
		}
		wg.Add(1)
		go func(t struct {
			name    string
			runner  func(context.Context, string, string, string, *slog.Logger) (string, error)
			enabled bool
		}) {
			defer wg.Done()

			// Acquire concurrency slot
			if err := state.limiter.Acquire(state.ctx); err != nil {
				state.logger.Warn("Could not acquire concurrency slot", "tool", t.name, "error", err)
				return
			}
			defer state.limiter.Release()

			proxy := ""
			if state.proxyManager != nil {
				proxy = state.proxyManager.GetNextProxy()
			}
			outputFile, err := t.runner(state.ctx, state.target, state.tempDir, proxy, state.logger)
			if err != nil {
				state.MarkPartialFail(t.name, err)
				return
			}
			mu.Lock()
			tempFiles = append(tempFiles, outputFile)
			mu.Unlock()
		}(tool)
	}
	wg.Wait()

	// Combina os resultados de todas as ferramentas em subdomains.txt
	return utils.CombineAndDeduplicateFiles(state.subdomainsFile, tempFiles...)
}

// stepRunBBot executa o bbot com o módulo de scan máximo para enumeração abrangente.
func stepRunBBot(state *reconState, bbotPresets []string, bbotModules []string) error {
	if !config.Cfg.Tools.Bbot.Enabled {
		state.logger.Info("BBot is disabled in config, skipping.")
		return nil
	}

	state.logger.Info("--- Starting: Comprehensive Enumeration (bbot) ---")

	outputDir := filepath.Join(state.resultsPath, "bbot") // Create a dedicated output directory for bbot
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for bbot: %w", err)
	}

	// Load base BBot configuration from tools.bbot
	bbotConfig := config.Cfg.Tools.Bbot

	// Merge configurations from all specified presets
	for _, presetName := range bbotPresets {
		if presetName == "" {
			continue
		}
		if preset, ok := config.Cfg.Recon.Presets[presetName]; ok && preset.BBot != nil {
			state.logger.Info("Applying BBot preset", "preset", presetName)
			// Merge logic: append slices, overwrite simple values
			// Presets
			bbotConfig.Presets = append(bbotConfig.Presets, preset.BBot.Presets...)
			// Flags
			bbotConfig.Flags = append(bbotConfig.Flags, preset.BBot.Flags...)
			// Modules
			bbotConfig.Modules = append(bbotConfig.Modules, preset.BBot.Modules...)
			// OutputModules
			bbotConfig.OutputModules = append(bbotConfig.OutputModules, preset.BBot.OutputModules...)
			// ExcludeModules
			bbotConfig.ExcludeModules = append(bbotConfig.ExcludeModules, preset.BBot.ExcludeModules...)
			// Blacklist
			bbotConfig.Blacklist = append(bbotConfig.Blacklist, preset.BBot.Blacklist...)
			// AllowDeadly
			if preset.BBot.AllowDeadly {
				bbotConfig.AllowDeadly = true
			}
			// RateLimit (take max or last)
			if preset.BBot.RateLimit > 0 {
				bbotConfig.RateLimit = preset.BBot.RateLimit
			}
			// Concurrency (take max or last)
			if preset.BBot.Concurrency > 0 {
				bbotConfig.Concurrency = preset.BBot.Concurrency
			}
			// Proxy (last one wins)
			if preset.BBot.Proxy != "" {
				bbotConfig.Proxy = preset.BBot.Proxy
			}
			// ExtraArgs
			bbotConfig.ExtraArgs = append(bbotConfig.ExtraArgs, preset.BBot.ExtraArgs...)
			// ConfigOverrides (merge maps)
			if bbotConfig.ConfigOverrides == nil {
				bbotConfig.ConfigOverrides = make(map[string]any)
			}
			for k, v := range preset.BBot.ConfigOverrides {
				bbotConfig.ConfigOverrides[k] = v
			}
		} else {
			state.logger.Warn("BBot preset not found or invalid, skipping.", "preset", presetName)
		}
	}

	// Append modules passed directly as arguments
	if len(bbotModules) > 0 {
		bbotConfig.Modules = append(bbotConfig.Modules, bbotModules...)
	}

	// Remove duplicatas da lista de módulos
	if len(bbotConfig.Modules) > 0 {
		seen := make(map[string]struct{})
		uniqueModules := []string{}
		for _, mod := range bbotConfig.Modules {
			if _, ok := seen[mod]; !ok {
				seen[mod] = struct{}{}
				uniqueModules = append(uniqueModules, mod)
			}
		}
		bbotConfig.Modules = uniqueModules
	}

	// Handle config_overrides
	var tempConfigFile string
	if len(bbotConfig.ConfigOverrides) > 0 {
		tempFile, err := os.CreateTemp(state.tempDir, "bbot_config_override_*.yml")
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

	// Define o proxy a ser usado, dando prioridade ao proxyManager da linha de comando
	// sobre a configuração do bbot.
	proxy := bbotConfig.Proxy
	if state.proxyManager != nil {
		proxy = state.proxyManager.GetNextProxy()
	}

	jsonFile, err := tools.RunBBot(
		state.ctx,
		state.target,         // Main target
		state.subdomainsFile, // Subdomains file
		outputDir,
		bbotConfig.AllowDeadly,
		bbotConfig.RateLimit,
		bbotConfig.Concurrency,
		proxy,
		state.logger,
		extraArgs...,
	)
	if err != nil {
		return fmt.Errorf("bbot execution failed: %w", err)
	}

	state.bbotJSONFile = jsonFile

	return nil
}

func stepRunDownloadJSContent(state *reconState) error {
	state.logger.Info("--- Starting: JavaScript Content Download ---")
	inputFile := state.liveSubdomainsFile
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		state.logger.Warn("Live subdomains file is empty, skipping JS content download.", "file", inputFile)
		return nil
	}

	jsFilesOutput := filepath.Join(state.resultsPath, "js-files.txt")

	// httpx -l scope.txt -timeout 3 -threads 300 -follow-redirects -silent
	httpxCmd := exec.CommandContext(state.ctx, "httpx",
		"-l", inputFile,
		"-timeout", "3",
		"-threads", "300",
		"-follow-redirects",
		"-silent",
	)

	// katana -silent -d 5 -jc -kf all
	katanaCmd := exec.CommandContext(state.ctx, "katana",
		"-silent",
		"-d", "5",
		"-jc",
		"-kf", "all",
	)

	// grep -Pi '.js(onp?)?$'
	grepCmd := exec.CommandContext(state.ctx, "grep", "-Pi", `.js(onp?)?$`)
	if runtime.GOOS == "windows" {
		// 'grep' não é padrão no Windows, 'findstr' pode ser uma alternativa, mas com regex diferente.
		// Por simplicidade, vamos pular o grep no Windows ou o usuário deve ter grep (ex: via Git Bash, WSL).
		state.logger.Warn("grep command might not be available on Windows. The toolchain may fail.")
	}

	// anew js-files.txt
	anewCmd := exec.CommandContext(state.ctx, "anew", jsFilesOutput)

	state.logger.Info("Executing toolchain for JS download", "chain", "httpx | katana | grep | anew")
	err := ExecuteToolChain(state.logger, httpxCmd, katanaCmd, grepCmd, anewCmd)
	if err != nil {
		return fmt.Errorf("javascript content download toolchain failed: %w", err)
	}

	state.logger.Info("JavaScript content download completed.", "output_file", jsFilesOutput)
	return nil
}

func ExecuteToolChain(logger *slog.Logger, cmds ...*exec.Cmd) error {
	for i, cmd := range cmds[:len(cmds)-1] {
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("failed to create stdout pipe for command %s: %w", cmd.Path, err)
		}
		cmds[i+1].Stdin = stdout
	}

	// Redireciona a saída do último comando para o os.Stdout/err para logging
	cmds[len(cmds)-1].Stdout = os.Stdout
	cmds[len(cmds)-1].Stderr = os.Stderr

	// Inicia os comandos em ordem reversa
	for i := len(cmds) - 1; i >= 0; i-- {
		if err := cmds[i].Start(); err != nil {
			return fmt.Errorf("failed to start command %s: %w", cmds[i].Path, err)
		}
	}

	// Espera pelos comandos em ordem normal
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			// Não retorna erro para todos os comandos, pois alguns podem terminar (ex: grep sem match)
			logger.Warn("A command in the toolchain finished with an error (this may be expected)", "command", cmd.Path, "error", err)
		}
	}

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
	}
	for name, stepFunc := range steps {
		if err := stepFunc(state); err != nil {
			state.logger.Warn("Web analysis step failed but continuing.", "sub_step", name, "error", err)
		}
	}
	state.logger.Info("Web Content Analysis Phase completed.")
	return nil
}

// addEndpointsToReconTargets extrai endpoints de achados HTML analisados
// e os adiciona ao arquivo unificado de alvos de recon.
func addEndpointsToReconTargets(state *reconState) error {
	if len(state.parsedHTMLFindings) == 0 {
		state.logger.Info("No HTML findings with endpoints to add to recon targets.")
		return nil
	}

	var newTargets []string
	for _, finding := range state.parsedHTMLFindings {
		baseURL, err := url.Parse(finding.URL)
		if err != nil {
			state.logger.Warn("Failed to parse base URL from finding", "url", finding.URL, "error", err)
			continue
		}

		for _, endpointFinding := range finding.Endpoints {
			// Asserção de tipo para acessar a struct concreta.
			contentFinding, ok := endpointFinding.(*types.ContentFinding)
			if !ok {
				state.logger.Warn("Failed to assert type for endpoint finding", "finding", endpointFinding)
				continue
			}
			match := contentFinding.Evidence
			parsedMatch, err := url.Parse(match)
			if err == nil && parsedMatch.IsAbs() {
				newTargets = append(newTargets, match)
			} else {
				resolvedURL := baseURL.ResolveReference(parsedMatch)
				newTargets = append(newTargets, resolvedURL.String())
			}
		}
	}

	if len(newTargets) > 0 {
		tempEndpointsFile, err := os.CreateTemp(state.tempDir, "html_endpoints_*.txt")
		if err != nil {
			return fmt.Errorf("failed to create temporary file for HTML endpoints: %w", err)
		}
		// defer os.Remove(tempEndpointsFile.Name()) // Desativado para depuração
		defer tempEndpointsFile.Close()

		if _, err := tempEndpointsFile.WriteString(strings.Join(newTargets, "\n")); err != nil {
			return fmt.Errorf("failed to write HTML endpoints to temp file: %w", err)
		}

		if err := utils.CombineAndDeduplicateFiles(state.reconTargetsFile, tempEndpointsFile.Name()); err != nil {
			return fmt.Errorf("failed to combine HTML endpoints with unified targets: %w", err)
		}
		state.logger.Info("Successfully added endpoints from HTML analysis to recon targets.", "count", len(newTargets))
	}
	return nil
}

func stepRunDetection(state *reconState) error {
	state.logger.Info("--- Starting: CVE Search and WAF Detection Phase ---")
	var wg sync.WaitGroup // FIX: A lógica de concorrência foi mantida para WAF e CVE Search.

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
	var proxy string
	if state.proxyManager != nil {
		proxy = state.proxyManager.GetNextProxy()
	}
	if err := tools.RunHttpx(state.ctx, inputFile, "", state.liveSubdomainsFile, state.tempDir, state.followRedirects, "", false, proxy, state.headers, state.cookies, state.username, state.password, state.logger); err != nil {
		state.logger.Warn("httpx command finished with a non-zero exit code. This is often expected if no live web hosts are found.", "error", err)
	}

	if utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Info("Httpx - Etapa 2: Detectando tecnologias nos hosts vivos...")
		if state.proxyManager != nil {
			proxy = state.proxyManager.GetNextProxy()
		}
		if err := tools.RunHttpx(state.ctx, state.liveSubdomainsFile, state.techFile, "", state.tempDir, state.followRedirects, "", true, proxy, state.headers, state.cookies, state.username, state.password, state.logger); err != nil {
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

// func parseFaviconHashes(filePath string, logger *slog.Logger) ([]types.FaviconResult, error) {
// 	if !utils.FileExistsAndIsNotEmpty(filePath) {
// 		return nil, nil
// 	}
// 	data, err := os.ReadFile(filePath)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to read favicon hashes file: %w", err)
// 	}
// 	return unmarshalFaviconResults(data, logger)
// }

func stepRunKatana(state *reconState) error {
	state.logger.Info("--- Starting: URL Collection (katana) ---")
	inputFile := state.liveSubdomainsFile
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		state.logger.Warn("Live subdomains file is empty, skipping Katana.", "file", inputFile)
		return nil
	}

	katanaConfig := config.Cfg.Tools.Katana

	// Ensure output directory exists
	katanaOutputDir := filepath.Join(state.resultsPath, "recon", "katana")
	if err := os.MkdirAll(katanaOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for katana: %w", err)
	}
	outputFile := filepath.Join(katanaOutputDir, "katana_deep.txt")

	// Prepare extra arguments, ensuring required ones are always present
	var extraArgs []string
	extraArgs = append(extraArgs, "-d", "5")    // Deep crawl
	extraArgs = append(extraArgs, "-jc")        // JavaScript parsing
	extraArgs = append(extraArgs, "-kf", "all") // Known files
	extraArgs = append(extraArgs, katanaConfig.ExtraArgs...)

	proxy := ""
	if state.proxyManager != nil {
		proxy = state.proxyManager.GetNextProxy()
	}

	err := tools.RunKatana(state.ctx, inputFile, outputFile, state.tempDir, proxy, state.headers, state.cookies, state.logger, extraArgs...)
	if err == nil && utils.FileExistsAndIsNotEmpty(outputFile) {
		if err := utils.CombineAndDeduplicateFiles(state.urlsFile, outputFile); err != nil {
			state.logger.Warn("Failed to add katana URLs to unified targets", "error", err)
		}
		state.logger.Info("URL Collection completed", "output_file", outputFile)
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
		// defer os.Remove(tempWaybackFile.Name()) // Desativado para depuração
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
	// Adiciona verificação para pular se a ferramenta estiver desabilitada na configuração.
	if !config.Cfg.Tools.Naabu.Enabled {
		state.logger.Info("Port scanning (naabu) is disabled in config, skipping.")
		return nil
	}

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

	// Se o arquivo de IPs estiver disponível, usa ele como entrada
	ipFile := filepath.Join(state.resultsPath, "recon", "targets_ip.txt")
	if utils.FileExistsAndIsNotEmpty(ipFile) {
		inputFile = ipFile
		hosts, err = utils.ReadLines(inputFile)
		if err != nil {
			state.logger.Warn("Failed to read targets_ip.txt, falling back to subdomainsFile", "error", err)
			inputFile = state.subdomainsFile
			// Re-read hosts from subdomainsFile
			hosts, _ = utils.ReadLines(inputFile)
		} else {
			state.logger.Info("Using resolved IPs for Port Scan", "file", ipFile)
		}
	}

	hostnames := make(map[string]struct{})
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		// Adiciona validação de IP aqui
		if utils.IsValidIP(h) { // FIX: Usando utils.IsValidIP
			hostnames[h] = struct{}{} // Adiciona o IP diretamente
		} else {
			// Tenta parsear como URL
			if u, err := url.Parse(h); err == nil && u.Hostname() != "" {
				hostnames[u.Hostname()] = struct{}{}
			} else {
				// Assume que é um domínio puro se não for URL válida ou IP
				// Remove protocolo se existir (caso url.Parse falhe por algum motivo estranho ou para garantir)
				h = strings.TrimPrefix(h, "http://")
				h = strings.TrimPrefix(h, "https://")
				// Remove porta se existir
				if strings.Contains(h, ":") {
					host, _, err := net.SplitHostPort(h)
					if err == nil {
						h = host
					}
				}
				if h != "" {
					hostnames[h] = struct{}{}
				}
			}
		}
	}

	tempInputFile, err := utils.WriteTempLines(hostnames, state.tempDir, "naabu_hosts_*.txt")
	if err != nil {
		return err
	}
	// defer os.Remove(tempInputFile) // Desativado para depuração

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
	state.logger.Info("--- Starting: WAF Detection (wafw00f) ---") // A verificação de 'enabled' já ocorre dentro de RunWafw00f.
	wafOutputFile := filepath.Join(state.resultsPath, "waf_results.json")
	if !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Warn("Live subdomains file is empty, skipping WAF detection.", "file", state.liveSubdomainsFile)
		return nil
	}

	err := tools.RunWafw00f(state.ctx, state.liveSubdomainsFile, wafOutputFile, state.tempDir, state.logger)
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

	// Limit concurrency for sitemap parsing
	concurrencyLimit := 10
	sem := make(chan struct{}, concurrencyLimit)

	var processSitemapURL func(sitemapURL string)
	processSitemapURL = func(sitemapURL string) {
		defer wg.Done()

		// Wait for resources before acquiring semaphore
		if gov := utils.GetGovernor(); gov != nil {
			if err := gov.WaitForResources(ctx); err != nil {
				return // Context canceled
			}
		}

		sem <- struct{}{}        // Acquire
		defer func() { <-sem }() // Release

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

func stepRunContentAnalysis(state *reconState) error {
	state.logger.Info("--- Starting: Unified Content Download and Static Analysis ---")

	// 1. Download Content with GoSpider
	gospiderOutputDir := filepath.Join(state.resultsPath, "content_analysis", "downloaded")
	if err := os.MkdirAll(gospiderOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for content analysis: %w", err)
	}

	proxy := ""
	if state.proxyManager != nil {
		proxy = state.proxyManager.GetNextProxy()
	}

	state.logger.Info("Downloading content with Katana...")
	// GoSpider takes a site as input. We can pass the root target or a list of URLs.
	// Passing the root target is safer for a broad crawl.
	// For better coverage, we could pass the live subdomains list if GoSpider supports it (it supports -S for sites list).
	// Let's use -S with live_subdomains.txt

	// We need to update RunGospider to accept a file list if we want to use -S.
	// The current wrapper uses -s (single site).
	// Let's update the wrapper first or just use the root target for now.
	// Using root target might miss subdomains.
	// Let's assume we update RunGospider to handle -S if input is a file.

	// Actually, let's just use the root target for this implementation to keep it simple as per wrapper.
	// Or better, let's iterate over live subdomains? No, that's too slow.
	// Let's use the wrapper as is with the target.

	// Using Katana to download content
	// -sr: Store Response
	// -srd: Store Response Directory
	katanaOutputList := filepath.Join(gospiderOutputDir, "index.txt")
	// Katana expects a file list for -list argument.
	// Create a temporary file containing the target.
	katanaInputFile := filepath.Join(state.tempDir, "katana_target.txt")
	var err error
	if err = os.WriteFile(katanaInputFile, []byte(state.target), 0644); err != nil {
		state.logger.Warn("Failed to create katana input file", "error", err)
	} else {
		err = tools.RunKatana(state.ctx, katanaInputFile, katanaOutputList, state.tempDir, proxy, state.headers, state.cookies, state.logger, "-sr", "-srd", gospiderOutputDir)
	}
	if err != nil {
		state.logger.Warn("Katana failed", "error", err)
		// Continue to analysis even if partial failure
	}

	// 2. Static Analysis with Semgrep
	state.logger.Info("Running Static Analysis with Semgrep...")
	semgrepOutputFile := filepath.Join(state.resultsPath, "content_analysis", "semgrep_findings.json")
	err = tools.RunSemgrep(state.ctx, gospiderOutputDir, semgrepOutputFile, state.logger)
	if err != nil {
		state.logger.Warn("Semgrep failed", "error", err)
	}

	// 3. Secret Scanning with Mantra (on URLs found by Gospider?)
	// Gospider outputs are in the directory. We can try to find a URL list there.
	// But Mantra is already in the workflow ("mantra" step).
	// The user asked to analyze the *downloaded content*.
	// Semgrep does that.
	// Mantra finds secrets in *responses* (live).
	// So running Mantra on the *downloaded files* would require Mantra to support file input, which the wrapper doesn't show.
	// We'll stick to Semgrep for file analysis.

	state.logger.Info("Unified Content Analysis completed.")
	return nil
}

func stepResolveTargetIP(state *reconState) error {
	state.logger.Info("--- Starting: Target IP Resolution ---")
	ipFile := filepath.Join(state.resultsPath, "recon", "target_ip.txt")

	// Create a temporary file with the target domain
	tempTargetFile := filepath.Join(state.tempDir, "target_domain.txt")
	if err := os.WriteFile(tempTargetFile, []byte(state.target), 0644); err != nil {
		return fmt.Errorf("failed to write target domain to temp file: %w", err)
	}

	if err := utils.ResolveIPs(tempTargetFile, ipFile); err != nil {
		state.logger.Warn("Failed to resolve target IP", "error", err)
		return nil // Non-fatal
	}

	state.logger.Info("Target IP resolution completed", "output_file", ipFile)
	return nil
}

func stepCleanSubdomains(state *reconState) error {
	state.logger.Info("--- Starting: Subdomain Cleaning and Deduplication ---")
	if !utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Info("No subdomains file to clean.")
		return nil
	}

	// Use ExtractDomainsFromURLFile which already handles cleaning and deduplication
	tempCleanFile := filepath.Join(state.tempDir, "clean_subdomains.txt")

	if err := utils.ExtractDomainsFromURLFile(state.subdomainsFile, tempCleanFile); err != nil {
		return fmt.Errorf("failed to clean subdomains: %w", err)
	}

	if err := os.Rename(tempCleanFile, state.subdomainsFile); err != nil {
		return fmt.Errorf("failed to replace subdomains file with clean version: %w", err)
	}

	state.logger.Info("Subdomain cleaning completed.")
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

func AnalyzeContentForPatterns(content string) (secrets []types.Finding, endpoints []types.Finding) {
	// Analisa segredos
	for _, pattern := range secretPatterns {
		// Encontra todas as correspondências únicas
		matches := utils.UniqueStrings(pattern.FindAllString(content, -1))
		for _, match := range matches {
			secrets = append(secrets, &types.ContentFinding{
				Tool:     "content-analysis",
				Evidence: match,
				Severity: "high", // Segredos são geralmente de alta severidade
				FType:    "Secret",
			})
		}
	}

	for _, pattern := range endpointPatterns {
		// Encontra todas as correspondências únicas
		matches := utils.UniqueStrings(pattern.FindAllString(content, -1))
		for _, match := range matches {
			endpoints = append(endpoints, &types.ContentFinding{
				Tool:     "content-analysis",
				Evidence: match,
				Severity: "info", // Endpoints são informativos
				FType:    "Endpoint",
			})
		}
	}
	return secrets, endpoints
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

func normalizeDomainsToURLs(domains []string) []string {
	uniqueURLs := make(map[string]struct{})
	for _, domain := range domains {
		// Adiciona uma verificação para ignorar entradas que parecem caminhos de arquivo.
		if domain == "" || strings.Contains(domain, "/") || !strings.Contains(domain, ".") {
			continue
		}

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

func RunCVESearch(ctx context.Context, techFile, outputFile string, logger *slog.Logger) error {
	// Adiciona verificação para pular se a ferramenta estiver desabilitada.
	if !config.Cfg.Tools.CVESearch.Enabled {
		logger.Info("CVE search is disabled in config, skipping.")
		return nil
	}

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
		// HttpxTechInfo é a struct para o output JSON bruto do Httpx.
		// Definida localmente pois só é usada aqui.
		type HttpxTechInfo struct {
			URL  string   `json:"url"`
			Tech []string `json:"tech"`
			Info struct {
				Title      string `json:"title"`
				StatusCode int    `json:"status_code"`
			} `json:"info"`
		}

		var info HttpxTechInfo
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

	// FIX: Removida a declaração de htmlFilesPath, pois não estava sendo utilizada.
	if err := os.MkdirAll(filepath.Join(state.resultsPath, "recon", "html_files"), 0755); err != nil {
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

func stepRunTruffleHog(state *reconState) error {
	state.logger.Info("--- Starting: Secret Scanning (TruffleHog) ---")
	if !config.Cfg.Tools.TruffleHog.Enabled {
		state.logger.Info("TruffleHog is disabled in config, skipping.")
		return nil
	}

	outputFile := filepath.Join(state.resultsPath, "trufflehog_findings.json")

	profile, ok := utils.GetActiveWAFProfile(state.logger, "", state.tempDir)
	rateLimit := config.Cfg.Tools.TruffleHog.RateLimit
	if rateLimit == 0 && ok {
		rateLimit = profile.RateLimit
	}
	concurrency := config.Cfg.Tools.TruffleHog.Concurrency
	if concurrency == 0 {
		concurrency = config.Cfg.Engine.MaxParallelTasks
	}
	proxy := config.Cfg.Tools.TruffleHog.Proxy
	if proxy == "" && ok {
		if len(profile.Proxies) > 0 {
			proxy = profile.Proxies[0]
		}
	}

	err := tools.RunTruffleHog(state.ctx, state.resultsPath, outputFile, rateLimit, concurrency, proxy, state.logger)
	if err != nil {
		state.MarkPartialFail("trufflehog", err)
		return nil // Not a fatal error
	}
	state.logger.Info("TruffleHog scan completed", "output_file", outputFile)
	return nil
}

func generateReconSummary(state *reconState) (string, []string, error) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **Recon Summary for: %s**\n\n", state.target))

	summary.WriteString(fmt.Sprintf("• **Subdomains Found:** %d\n", utils.CountLines(state.subdomainsFile)))
	summary.WriteString(fmt.Sprintf("• **Live Hosts:** %d\n", utils.CountLines(state.liveSubdomainsFile)))
	summary.WriteString(fmt.Sprintf("• **URLs Discovered:** %d\n", utils.CountLines(state.urlsFile)))

	htmlSecretCount := 0
	htmlEndpointCount := 0
	for _, f := range state.parsedHTMLFindings {
		htmlSecretCount += len(f.Secrets)
		htmlEndpointCount += len(f.Endpoints)
	}
	if htmlSecretCount > 0 || htmlEndpointCount > 0 {
		summary.WriteString(fmt.Sprintf("• **HTML Analysis:** Found %d potential secrets and %d endpoints.\n", htmlSecretCount, htmlEndpointCount))
	}
	return summary.String(), []string{state.subdomainsFile, state.liveSubdomainsFile, state.urlsFile, state.htmlFindingsFile, state.techFile, state.reconTargetsFile}, nil
}

func stepRunUncover(state *reconState) error {
	if !config.Cfg.Tools.Uncover.Enabled {
		state.logger.Info("Skipping Uncover (disabled)")
		return nil
	}

	state.logger.Info("Running Uncover for passive asset discovery...")
	uncoverOutputFile := filepath.Join(state.resultsPath, "uncover_assets.txt")

	// Use target domain as query
	err := tools.RunUncover(state.ctx, state.target, uncoverOutputFile, state.tempDir, state.logger)
	if err != nil {
		state.logger.Warn("Uncover failed", "error", err)
		return nil // Non-fatal
	}

	if utils.FileExistsAndIsNotEmpty(uncoverOutputFile) {
		state.logger.Info("Uncover found assets", "file", uncoverOutputFile)
		// Merge into subdomains file
		if err := utils.CombineAndDeduplicateFiles(state.subdomainsFile, state.subdomainsFile, uncoverOutputFile); err != nil {
			state.logger.Warn("Failed to merge uncover results", "error", err)
		}
	}

	return nil
}
