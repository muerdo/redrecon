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
	"os/exec"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	
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

		// Chaves de Provedores Cloud
		regexp.MustCompile(`(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`), // AWS Access Key ID
		regexp.MustCompile(`(?i)aws_secret_access_key\s*=\s*['\"][0-9a-zA-Z\/\+]{40}['\"]`),
		regexp.MustCompile(`(?i)ghp_[0-9a-zA-Z]{36}`), // GitHub Personal Access Token
		regexp.MustCompile(`(?i)glpat-[0-9a-zA-Z_\-]{20}`), // GitLab Personal Access Token

		// Chaves Privadas
		regexp.MustCompile(`-----BEGIN (RSA|EC|PGP|OPENSSH) PRIVATE KEY-----`),

		// Outras informações sensíveis
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

func SanitizeTargetForPath(target string) string {
	replacer := strings.NewReplacer("http://", "", "https://", "", ":", "_", "/", "_", "?", "_", "&", "_", "=", "_")
	return replacer.Replace(target)
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
	techFile             string
	htmlFindingsFile     string
	subdomainWordlist    string
	fuzzWordlist         string
	tempDir              string // Diretório temporário para esta execução de recon
	logger               *slog.Logger // Custom logger for this recon instance
}

// GetLiveSubdomainsFilePath retorna o caminho esperado para o arquivo live_subdomains.txt de um alvo.
func GetLiveSubdomainsFilePath(taskIdentifier string) string {
	sanitizedTaskIdentifier := SanitizeTargetForPath(taskIdentifier)
	return filepath.Join("results", sanitizedTaskIdentifier, "recon", "live_subdomains.txt")
}

type reconStep func(state *reconState) error

func StartRecon(taskIdentifier string, rootTarget string, initialSubdomains []string, skipSteps []string, followRedirects bool, isInteractive bool, logger *slog.Logger) (string, []string, error) {
	slog.Info("Starting reconnaissance process", "target", rootTarget)

	sanitizedTaskIdentifier := SanitizeTargetForPath(taskIdentifier)
	resultsPath := filepath.Join("results", sanitizedTaskIdentifier, "recon")
	slog.Info("Creating output directory", "path", resultsPath)

	err := os.MkdirAll(resultsPath, 0755)
	if err != nil && !os.IsExist(err) { // Check if error is not just directory already existing
		slog.Error("Failed to create directory", "path", resultsPath, "error", err)
		return "", nil, fmt.Errorf("could not create directory %s: %w", resultsPath, err)
	}

	// Cria um diretório temporário dentro da pasta de resultados do alvo.
	tempDir := filepath.Join(resultsPath, "tmp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create temporary directory for recon: %w", err)
	}

	state := &reconState{
		ctx:                context.Background(),
		target:             rootTarget,
		resultsPath:        resultsPath,
		followRedirects:    followRedirects,
		subdomainsFile:     filepath.Join(resultsPath, "subdomains.txt"),
		liveSubdomainsFile: filepath.Join(resultsPath, "live_subdomains.txt"),
		urlsFile:           filepath.Join(resultsPath, "urls.txt"),
		jsFindingsFile:     filepath.Join(resultsPath, "js_findings.txt"),
		logger:             logger, // Assign the custom logger
		techFile:           filepath.Join(resultsPath, "httpx_tech.json"),
		htmlFindingsFile:   filepath.Join(resultsPath, "html_findings.txt"),
		subdomainWordlist:  config.Cfg.Wordlists.Subdomains,
		fuzzWordlist:       config.Cfg.Wordlists.Fuzzing,
		tempDir:            tempDir,
	}

	// Se subdomínios iniciais foram fornecidos, escreve-os no arquivo de subdomínios.
	if len(initialSubdomains) > 0 {
		if err := combineAndDeduplicateURLs(state.subdomainsFile, initialSubdomains); err != nil {
			return "", nil, fmt.Errorf("failed to write initial subdomains: %w", err)
		}
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	workflow := map[string]reconStep{
		"subfinder":     stepRunSubfinder,
		"shuffledns":    stepRunShuffleDNS,
		"httpx":         stepRunHttpx,
		"favicon":       stepRunFaviconHash,
		"waf":           stepRunWafw00f,
		"sitemap":       stepGetSitemapURLs,
		"htmlanalysis":  stepRunHTMLAnalysis,
		"ffuf":          stepRunFuzzing,
		"csp":           stepGetCSPDomains,
		"portscan":      stepRunPortScan,
		"katana":        stepRunKatana,
		"wayback":       stepGetWaybackURLs,
		"jsanalysis":    stepRunJSAnalysis,
	}

	executionOrder := []string{ // Define the order of execution
		"subfinder", "shuffledns", "httpx", "portscan", "favicon", "waf", "csp", "sitemap", "katana", "wayback", "htmlanalysis", "jsanalysis", "ffuf",
	}

	logger.Info("Output directory created successfully. Starting reconnaissance tasks.")

	if isInteractive {
		// Lógica interativa para pular etapas
		skipInputChan := make(chan string)
		go func() {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				skipInputChan <- strings.TrimSpace(scanner.Text())
			}
		}()

		for _, stepName := range executionOrder {
			if _, shouldSkip := skipSet[stepName]; shouldSkip {
				state.logger.Warn("Skipping step as requested", "step", stepName)
				continue
			}

			stepFunc := workflow[stepName]
			stepCtx, cancelStep := context.WithCancel(state.ctx)
			defer cancelStep()
			errChan := make(chan error, 1)

			fmt.Printf("\n-> Press 's' and Enter to skip the current step: [%s]\n", stepName)
			state.logger.Info(fmt.Sprintf("Starting step: %s", stepName))
			go func() {
				stepState := *state
				stepState.ctx = stepCtx
				errChan <- stepFunc(&stepState)
			}()

			select {
			case err := <-errChan:
				if err != nil {
					state.logger.Error("A reconnaissance step failed", "step", stepName, "error", err)
				}
			case input := <-skipInputChan:
				if strings.ToLower(input) == "s" {
					state.logger.Warn("User requested to skip step. Cancelling...", "step", stepName)
					cancelStep()
					<-errChan
				}
			case <-state.ctx.Done():
				slog.Info("Reconnaissance process cancelled.", "error", state.ctx.Err())
				cancelStep()
				return "", nil, state.ctx.Err()
			}
		}
	} else {
		// Lógica não interativa (para o 'chain')
		for _, stepName := range executionOrder {
			if _, shouldSkip := skipSet[stepName]; shouldSkip {
				state.logger.Warn("Skipping step as requested", "step", stepName)
				continue
			}
			state.logger.Info(fmt.Sprintf("Starting step: %s", stepName))
			if err := workflow[stepName](state); err != nil { // O erro já é logado dentro da função do passo
				state.logger.Error("A reconnaissance step failed", "step", stepName, "error", err)
			}
		}
	}

	slog.Info("Reconnaissance process completed.")
	return generateReconSummary(state)
}

func stepRunSubfinder(state *reconState) error {
	state.logger.Info("--- Starting: Passive Subdomain Enumeration (subfinder) ---")
	// Foco no subfinder por ser rápido e eficaz. Amass e outros podem ser adicionados de volta se necessário.

	// Define a ordem de prioridade para a execução das ferramentas de enumeração.
	// sublist3r é priorizado por não depender de chaves de API.
	orderedTools := []struct {
		name    string
		runFunc func(context.Context, string, string, string, *slog.Logger) error
	}{
		{"sublist3r", runSublist3r},
		{"subfinder", runSubfinder},
		{"amass", runAmass},
	}

	var tempFiles []string

	for _, tool := range orderedTools {
		// Verifica se o contexto foi cancelado antes de iniciar uma nova ferramenta.
		if state.ctx.Err() != nil {
			state.logger.Warn("Reconnaissance cancelled, stopping subdomain enumeration.", "error", state.ctx.Err())
			break
		}

		if !CommandExists(tool.name) {
			state.logger.Warn(fmt.Sprintf("%s is not installed or not executable. Skipping.", tool.name), "tool", tool.name)
			continue
		}

		tempOutputFile := filepath.Join(state.tempDir, fmt.Sprintf("%s_output.txt", tool.name))
		if runErr := tool.runFunc(state.ctx, state.target, tempOutputFile, state.tempDir, state.logger); runErr != nil {
			state.logger.Warn("Subdomain enumeration tool finished with an error.", "tool", tool.name)
		}
		if FileExistsAndIsNotEmpty(tempOutputFile) {
			tempFiles = append(tempFiles, tempOutputFile)
		}
	}

	// Consolida os resultados de todos os arquivos temporários.
	var allSubdomains []string
	for _, f := range tempFiles {
		subs, err := ReadLines(f)
		if err == nil {
			allSubdomains = append(allSubdomains, subs...)
		}
		os.Remove(f) // Limpa o arquivo temporário.
	}

	if err := combineAndDeduplicateURLs(state.subdomainsFile, allSubdomains); err != nil {
		return fmt.Errorf("failed to consolidate subdomain results: %w", err)
	}

	if FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Info("Passive Subdomain Enumeration completed", "output_file", state.subdomainsFile)
	} else {
		// Se, após todas as ferramentas, nenhum subdomínio for encontrado, não há como continuar.
		state.logger.Error("Passive subdomain enumeration finished, but no subdomains were found. Stopping recon.", "target", state.target)
		return fmt.Errorf("no subdomains found for %s after passive enumeration", state.target)
	}
	return nil
}

func stepRunFaviconHash(state *reconState) error {
	state.logger.Info("--- Starting: Favicon Hash Analysis ---")
	faviconOutputFile := filepath.Join(state.resultsPath, "favicon_hashes.json")
	err := runFaviconHash(state.ctx, state.liveSubdomainsFile, faviconOutputFile, state.logger)
	if err != nil {
		return err
	}
	if FileExistsAndIsNotEmpty(faviconOutputFile) {
		state.logger.Info("Favicon analysis completed", "output_file", faviconOutputFile)
	}
	return nil
}

func stepRunShuffleDNS(state *reconState) error {
	if !CommandExists("shuffledns") {
		state.logger.Error("shuffledns is not installed or not executable. Please check your PATH and permissions.", "tool", "shuffledns")
		return fmt.Errorf("shuffledns not found or not executable")
	}
	state.logger.Info("--- Starting: Active Subdomain Enumeration (shuffledns) ---")
	foundSubdomains, err := runShuffleDNS(state.ctx, state.target, state.subdomainWordlist, state.subdomainsFile, state.tempDir, state.logger)
	if err != nil {
		return err
	}
	if len(foundSubdomains) > 0 {
		state.logger.Info("Active Subdomain Enumeration completed", "new_subdomains", len(foundSubdomains))
		return combineAndDeduplicateURLs(state.subdomainsFile, foundSubdomains)
	}
	state.logger.Info("Active Subdomain Enumeration completed with no new findings.")
	return nil
}

func stepRunHttpx(state *reconState) error {
	if !CommandExists("httpx") {
		state.logger.Error("httpx is not installed or not executable. Please check your PATH and permissions.", "tool", "httpx")
		return fmt.Errorf("httpx not found or not executable")
	}
	state.logger.Info("--- Starting: Live Subdomain Validation (httpx) ---")
	err := runHttpx(state.ctx, state.subdomainsFile, state.liveSubdomainsFile, state.techFile, state.tempDir, state.followRedirects, state.logger)
	if err == nil {
		state.logger.Info("Live Subdomain Validation completed", "output_file", state.liveSubdomainsFile)
	} // Se err não for nil, ele será retornado por stepRunHttpx
	return err
}

func stepRunHTMLAnalysis(state *reconState) error {
	state.logger.Info("--- Starting: HTML Source Code Analysis ---")
	// Passa o estado completo para que a função tenha acesso ao resultsPath.
	if err := runHTMLAnalysis(state); err != nil {
		return err
	}
	if FileExistsAndIsNotEmpty(state.htmlFindingsFile) {
		state.logger.Info("HTML analysis completed", "output_file", state.htmlFindingsFile)
	} else {
		state.logger.Info("HTML analysis completed with no new findings.")
	}
	return nil
}

func stepRunFuzzing(state *reconState) error {
	if !CommandExists("ffuf") {
		state.logger.Error("ffuf is not installed or not executable. Please check your PATH and permissions.", "tool", "ffuf")
		return fmt.Errorf("ffuf not found or not executable")
	}
	state.logger.Info("--- Starting: Directory and File Fuzzing (ffuf) ---")
	fuzzResultsDir := filepath.Join(state.resultsPath, "ffuf_results")

	var ffufRateLimit int
	if config.Cfg.Engine.WAF.Enabled {
		profile := config.Cfg.Engine.WAF.DefaultProfile
		ffufRateLimit = profile.RateLimit
		state.logger.Info("Applying default WAF rate limit for Fuzzing (ffuf).", "rate_limit", ffufRateLimit)
	}

	// Executa ffuf e dirsearch em paralelo para maximizar a cobertura de fuzzing.
	var wg sync.WaitGroup
	errChan := make(chan error, 2)

	wg.Add(1)
	go func() {
		defer wg.Done()
		state.logger.Info("Starting ffuf fuzzing...")
		if err := RunFfuf(state.ctx, state.liveSubdomainsFile, state.fuzzWordlist, fuzzResultsDir, ffufRateLimit, state.logger); err != nil {
			errChan <- err
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		state.logger.Info("Starting dirsearch fuzzing...")
		dirsearchOutputDir := filepath.Join(state.resultsPath, "dirsearch_results")
		if err := runDirsearch(state.ctx, state.liveSubdomainsFile, state.fuzzWordlist, dirsearchOutputDir, ffufRateLimit, state.logger); err != nil {
			errChan <- err
		}
	}()

	wg.Wait()
	close(errChan)

	// Captura o primeiro erro, se houver.
	err := <-errChan
	if err != nil {
		return err
	}

	// Check if the directory was created and is not empty
	if dirExistsAndIsNotEmpty(fuzzResultsDir) {
		state.logger.Info("Fuzzing completed", "output_dir", fuzzResultsDir)
	} else {
		state.logger.Info("Fuzzing completed with no findings.")
	}
	return nil
}

func stepRunKatana(state *reconState) error {
	if !CommandExists("katana") {
		state.logger.Error("katana is not installed or not executable. Please check your PATH and permissions.", "tool", "katana")
		return fmt.Errorf("katana not found or not executable")
	}
	state.logger.Info("--- Starting: URL Collection (katana) ---")
	err := runKatana(state.ctx, state.liveSubdomainsFile, state.urlsFile, state.tempDir, state.logger) // O erro já é logado dentro da função
	if err == nil {
		state.logger.Info("URL Collection completed", "output_file", state.urlsFile)
	}
	return err
}

func stepRunJSAnalysis(state *reconState) error {
	state.logger.Info("--- Starting: JavaScript Analysis ---")
	err := runJSAnalysis(state.ctx, state.urlsFile, state.jsFindingsFile, state.logger)
	if err == nil && FileExistsAndIsNotEmpty(state.jsFindingsFile) {
		state.logger.Info("JavaScript Analysis completed", "output_file", state.jsFindingsFile)
	}
	return err
}

func stepGetWaybackURLs(state *reconState) error { // This function needs logger too
	state.logger.Info("--- Starting: Augmenting with Wayback Machine URLs ---")
	waybackURLs, err := getWaybackURLs(state.ctx, state.target, state.logger)
	if err != nil {
		state.logger.Warn("Failed to get URLs from Wayback Machine, but continuing...", "error", err)
		return nil
	}
	if len(waybackURLs) > 0 {
		err = combineAndDeduplicateURLs(state.urlsFile, waybackURLs)
		if err != nil {
			return fmt.Errorf("failed to combine Wayback URLs: %w", err)
		}
		state.logger.Info("Successfully added URLs from Wayback Machine", "count", len(waybackURLs))
	}
	return nil
}

func stepRunPortScan(state *reconState) error {
	if !CommandExists("naabu") {
		state.logger.Warn("naabu is not installed, skipping port scan.", "help", "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
		return nil
	}
	state.logger.Info("--- Starting: Port Scanning (naabu) ---")
	portScanOutputFile := filepath.Join(state.resultsPath, "portscan_results.txt")
	err := runPortScan(state.ctx, state.liveSubdomainsFile, portScanOutputFile, state.logger)
	if err != nil {
		return err
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
	err := runWafw00f(state.ctx, state.liveSubdomainsFile, wafOutputFile, state.logger)
	if err != nil {
		return err // O erro já é logado dentro da função
	}
	state.logger.Info("WAF detection completed", "output_file", wafOutputFile)
	return nil
}

func stepGetSitemapURLs(state *reconState) error {
	state.logger.Info("--- Starting: Sitemap URL Extraction ---")
	// Usamos o target principal, pois sitemaps geralmente estão no domínio raiz.
	sitemapURLs, err := parseSitemap(state.ctx, state.target, state.logger)
	if err != nil {
		state.logger.Warn("Failed to get URLs from sitemap, but continuing...", "error", err)
		return nil // Não é um erro fatal
	}
	if len(sitemapURLs) > 0 {
		if err := combineAndDeduplicateURLs(state.urlsFile, sitemapURLs); err != nil {
			return fmt.Errorf("failed to combine sitemap URLs: %w", err)
		}
		state.logger.Info("Successfully added URLs from sitemap", "count", len(sitemapURLs))
	}
	return nil
}

func stepGetCSPDomains(state *reconState) error {
	state.logger.Info("--- Starting: CSP Header Subdomain Extraction ---")
	cspDomains, err := getCSPDomains(state.ctx, state.liveSubdomainsFile, state.target, state.logger)
	if err != nil { // This function needs logger too
		state.logger.Warn("Failed to get subdomains from CSP headers, but continuing...", "error", err)
		return nil
	}
	if len(cspDomains) > 0 {
		state.logger.Info("Found new potential subdomains from CSP headers", "count", len(cspDomains))
		return combineAndDeduplicateURLs(state.subdomainsFile, cspDomains)
	}
	state.logger.Info("CSP Header Subdomain Extraction completed with no new findings.")
	return nil
}

// FileExistsAndIsNotEmpty verifica se um arquivo existe e não está vazio.
// Tornada pública para ser usada por outros pacotes.
func FileExistsAndIsNotEmpty(path string) bool {
	stat, err := os.Stat(path)
	return !os.IsNotExist(err) && stat.Size() > 0
}

func dirExistsAndIsNotEmpty(path string) bool {
	entries, err := os.ReadDir(path)
	// Return true if there's no error and there's at least one entry in the directory.
	return err == nil && len(entries) > 0
}

// CommandExists checks if a command exists in the system's PATH.
func CommandExists(cmd string) bool {
	path, err := exec.LookPath(cmd)
	if err != nil {
		return false
	}
	// Check if the file is executable
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return info.Mode()&0111 != 0
}

// executeCommand é uma função auxiliar para executar comandos externos de forma padronizada.
// Ela lida com a captura de stderr, logging e tratamento de erros comuns.
// Retorna o stdout do comando e um erro formatado em caso de falha.
func ExecuteCommand(ctx context.Context, logger *slog.Logger, toolName string, args ...string) (string, error) {
	logger.Info(fmt.Sprintf("Executing external command: %s", toolName), "args", args)

	cmd := exec.CommandContext(ctx, config.GetToolPath(toolName), args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// Se o contexto foi cancelado, o erro é esperado, mas não é uma falha da ferramenta.
		if ctx.Err() == context.Canceled {
			logger.Warn("Command execution was cancelled", "tool", toolName)
			return "", nil // Retorna string vazia e nil para indicar que foi um cancelamento.
		}
		// Retorna um erro formatado com o stderr para fornecer contexto completo ao chamador.
		return "", fmt.Errorf("%s execution failed: %w\nStderr: %s", toolName, err, stderr.String())
	}

	// Loga o stderr mesmo em caso de sucesso, pois algumas ferramentas o usam para informações de status.
	if stderr.Len() > 0 {
		logger.Debug("Command finished with output on stderr", "tool", toolName, "stderr", stderr.String())
	}

	return stdout.String(), nil
}

func runSubfinder(ctx context.Context, target, outputFile, tempDir string, logger *slog.Logger) error {
	logger.Info("Starting subfinder", "target", target)
	logger.Info("API keys should be configured in the default provider-config.yaml file.")

	args := []string{"-d", target, "-o", outputFile, "-t", "50", "-timeout", "30", "-tmp-dir", tempDir, "-max-time", "600"}
	if _, err := ExecuteCommand(ctx, logger, "subfinder", args...); err != nil {
		// A lógica do subfinder é especial: mesmo que falhe, queremos continuar se já houver dados.
		// Por isso, logamos o erro mas não o retornamos para cima na cadeia.
		if !FileExistsAndIsNotEmpty(outputFile) {
			logger.Warn("Subfinder command failed and produced no output. This is often due to missing API keys in provider-config.yaml.", "error", err)
		} else {
			logger.Error("Subfinder command finished with an error, but an output file was found. Proceeding with existing data.", "error", err)
		}
	}

	return nil
}

func runAmass(ctx context.Context, target, outputFile, tempDir string, logger *slog.Logger) error {
	logger.Info("Starting amass", "target", target)
	logger.Info("Executing external amass command. This may take some time.")
	args := []string{
		"enum",
		"-passive", // Modo passivo para não enviar tráfego para o alvo
		"-d", target,
		"-o", outputFile,
		"-dir", filepath.Join(tempDir, "amass_cache"), // Usa um diretório de cache temporário
	}
	if _, err := ExecuteCommand(ctx, logger, "amass", args...); err != nil {
		logger.Error("Amass command failed", "error", err)
		return err
	}

	return nil
}

func runSublist3r(ctx context.Context, target, outputFile, tempDir string, logger *slog.Logger) error {
	logger.Info("Starting sublist3r", "target", target)

	// Sublist3r é uma ferramenta Python, pode precisar de flags específicas.
	// A flag -o salva a saída em um arquivo.
	args := []string{"-d", target, "-o", outputFile}
	if _, err := ExecuteCommand(ctx, logger, "sublist3r", args...); err != nil {
		logger.Error("Sublist3r command failed", "error", err)
		return err
	}
	return nil // Retorna nil em caso de sucesso
}

func runHttpx(ctx context.Context, inputFile, liveHostsOutputFile, techOutputFile, tempDir string, followRedirects bool, logger *slog.Logger) error {
	logger.Info("Starting httpx to find live subdomains", "input", inputFile)

	if !FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for httpx does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	// --- Primeira chamada ao httpx: Encontrar hosts ativos ---
	logger.Info("Running httpx to find live hosts...")
	argsLive := []string{
		"-l", inputFile,
		"-o", liveHostsOutputFile,
		"-threads", "50",
		"-no-color",
		"-random-agent",
		"-timeout", "10",
		"-tmp-dir", tempDir, // Força o httpx a usar nosso diretório temporário
	}
	if followRedirects {
		argsLive = append(argsLive, "-follow-redirects")
	}

	if _, err := ExecuteCommand(ctx, logger, "httpx", argsLive...); err != nil {
		// Se o httpx falhar e não produzir saída, é provável que seja um erro de configuração/execução.
		// Registramos um aviso forte, mas retornamos nil para não quebrar a cadeia de recon.
		if !FileExistsAndIsNotEmpty(liveHostsOutputFile) {
			logger.Warn("httpx command failed and produced no output. Check for configuration or permission issues.", "error", err)
			return nil
		}
		logger.Error("httpx command finished with an error, but an output file was found. Proceeding with existing data.", "error", err)
	}

	// Verifica se algum host ativo foi encontrado antes de prosseguir
	if !FileExistsAndIsNotEmpty(liveHostsOutputFile) {
		// Se o comando foi executado (err == nil) mas não produziu saída,
		// isso pode indicar um problema, mas não deve parar o fluxo.
		// Apenas registramos um aviso e retornamos nil para que outras etapas possam continuar.
		logger.Warn("httpx did not find any live hosts. Skipping technology detection.", "input", inputFile)
		return nil // Não é um erro, apenas não há nada para fazer
	}

	// --- Segunda chamada ao httpx: Detectar tecnologias nos hosts ativos ---
	logger.Info("Running httpx for technology detection on live hosts...")
	argsTech := []string{
		"-l", liveHostsOutputFile, // Usa a lista de hosts ativos como entrada
		"-tech-detect",
		"-json",
		"-o", techOutputFile,
		"-no-color",
		"-tmp-dir", tempDir, // Força o httpx a usar nosso diretório temporário
	}
	if _, err := ExecuteCommand(ctx, logger, "httpx", argsTech...); err != nil {
		return fmt.Errorf("httpx tech-detect execution failed: %w", err)
	}

	return nil
}

func runKatana(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	if !FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for Katana does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	logger.Info("Starting Katana to crawl for URLs", "input", inputFile)

	args := []string{
		// O Katana usa '-u' para uma única URL ou '-list' para uma lista.
		// Como estamos sempre passando um arquivo, usamos '-list'.
		"-list", inputFile,
		"-output", outputFile,
		"-silent",
		"-depth", "3",
		"-field-scope", "rdn",
		"-body-read-size", "2097152",
		"-timeout", "15",
		"-retry", "1",
		"-concurrency", "10",
		"-parallelism", "10",
		"-known-files", "all",
		"-tmp-dir", tempDir, // Força o katana a usar nosso diretório temporário
	}

	if _, err := ExecuteCommand(ctx, logger, "katana", args...); err != nil {
		// Katana pode falhar, mas não queremos que isso quebre a cadeia. Logamos e continuamos.
		logger.Error("Katana execution failed", "error", err)
	}

	// Se o comando foi executado com sucesso, mas não criou um arquivo de saída,
	// isso não é necessariamente um erro (pode não ter encontrado URLs), então apenas registramos.
	if !FileExistsAndIsNotEmpty(outputFile) {
		logger.Info("Katana ran successfully but found no new URLs.", "input", inputFile)
	}

	return nil
}

func combineAndDeduplicateURLs(filePath string, newURLs []string) error {
	existingURLs := make(map[string]struct{})

	file, err := os.Open(filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to open URL file for reading: %w", err)
		}
	} else {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			existingURLs[scanner.Text()] = struct{}{}
		}
		file.Close()
		if err := scanner.Err(); err != nil {
			return err
		}
	}

	for _, u := range newURLs {
		cleanURL := strings.TrimSpace(u)
		if cleanURL != "" {
			existingURLs[cleanURL] = struct{}{}
		}
	}

	output, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to open URL file for writing: %w", err)
	}
	defer output.Close()

	writer := bufio.NewWriter(output)
	for u := range existingURLs {
		_, _ = writer.WriteString(u + "\n")
	}

	return writer.Flush()
}

// ReadLines lê todas as linhas de um arquivo e as retorna como um slice de strings.
// Tornada pública para ser usada por outros pacotes.
func ReadLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

func getWaybackURLs(ctx context.Context, domain string, logger *slog.Logger) ([]string, error) { // This function needs logger too
	logger.Info("Fetching URLs from Wayback Machine", "domain", domain)
	apiURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)

	client := &http.Client{Timeout: 90 * time.Second}
	var resp *http.Response
	var err error
	maxRetries := 2

	for i := 0; i < maxRetries; i++ {
		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create Wayback Machine request: %w", err)
		}

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

	// Adiciona uma verificação de segurança para garantir que resp não seja nulo antes de prosseguir.
	if resp == nil {
		return nil, fmt.Errorf("received nil response from Wayback Machine after retries")
	}
	defer resp.Body.Close() // Esta linha agora é segura.

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

		client := &http.Client{Timeout: 20 * time.Second}
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

func IsMetadataTarget(urlStr string) bool { // This function needs logger too
	lowerURL := strings.ToLower(urlStr)
	extensions := []string{".pdf", ".jpg", ".jpeg", ".png", ".gif"}
	for _, ext := range extensions {
		if strings.HasSuffix(lowerURL, ext) {
			return true
		}
	}
	return false
}
// This function needs logger too
func AnalyzeFileMetadata(wg *sync.WaitGroup, urlStr string, writer *bufio.Writer, mu *sync.Mutex, logger *slog.Logger) {
	defer wg.Done()
	logger.Debug("Analyzing file for metadata", "url", urlStr)

	resp, err := http.Get(urlStr)
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

func GetJSURLsFromFile(inputFile string) ([]string, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file %s: %w", inputFile, err)
	}
	defer file.Close()

	var jsURLs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Check if the URL contains .js before a query string, or ends with .js
		if strings.Contains(line, ".js?") || strings.HasSuffix(line, ".js") {
			// Clean the URL by removing query parameters
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

func DownloadContent(urlStr string) ([]byte, error) { // This function needs logger too
	resp, err := http.Get(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to download from %s: %w", urlStr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("non-200 status code %d from %s", resp.StatusCode, urlStr)
	}

	return io.ReadAll(resp.Body)
}

// beautifyJS executa a ferramenta externa 'jsbeautifier-go' para formatar o código JS. // This function needs logger too
func beautifyJS(jsContent string, urlStr string, logger *slog.Logger) string {
	cmd := exec.Command("jsbeautifier-go")
	cmd.Stdin = strings.NewReader(jsContent)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		logger.Warn("Failed to run 'jsbeautifier-go'. Analyzing original content.", "url", urlStr, "error", err, "help", "Ensure 'jsbeautifier-go' is installed: go install github.com/ditashi/jsbeautifier-go@latest") // This function needs logger too
		return jsContent // Retorna o conteúdo original em caso de falha
	}
	return out.String()
}

// Finding representa um único achado de um padrão.
type Finding struct {
	Pattern string
	Matches map[string]int // Match -> Count
}

// analyzeContentForPatterns verifica o conteúdo em busca de segredos e endpoints.
func AnalyzeContentForPatterns(content string) (secrets []Finding, endpoints []Finding) {
	// Analisa segredos
	for _, pattern := range secretPatterns {
		matches := pattern.FindAllString(content, -1)
		if len(matches) > 0 {
			matchCounts := make(map[string]int)
			for _, m := range matches {
				matchCounts[m]++
			}
			secrets = append(secrets, Finding{
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
			endpoints = append(endpoints, Finding{
				Pattern: pattern.String(),
				Matches: matchCounts,
			})
		}
	}
	return secrets, endpoints
}

type URLFindings struct {
	URL       string
	Secrets   []Finding
	Endpoints []Finding
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
		findings := URLFindings{
			URL:       jsURL,
			Secrets:   jsSecrets,
			Endpoints: jsEndpoints,
		}
		WriteFindings(writer, mu, "JS", findings)
	}

	findAndAnalyzeSourcemap(jsURL, beautifiedContent, writer, mu, logger)
}

func WriteFindings(writer *bufio.Writer, mu *sync.Mutex, sourceType string, findings URLFindings) {
	mu.Lock()
	defer mu.Unlock()

	_, _ = writer.WriteString(fmt.Sprintf("--- Findings in [%s] from URL: %s ---\n", sourceType, findings.URL))
	if len(findings.Secrets) > 0 {
		_, _ = writer.WriteString("  [SECRETS]\n")
		for _, s := range findings.Secrets {
			_, _ = writer.WriteString(fmt.Sprintf("    - Pattern: %s\n", s.Pattern))
			for match, count := range s.Matches {
				_, _ = writer.WriteString(fmt.Sprintf("      - Match: %-30s (Count: %d)\n", `"`+match+`"`, count))
			}
		}
	}
	if len(findings.Endpoints) > 0 {
		_, _ = writer.WriteString("  [ENDPOINTS]\n")
		for _, e := range findings.Endpoints {
			_, _ = writer.WriteString(fmt.Sprintf("    - Pattern: %s\n", e.Pattern))
			for match, count := range e.Matches {
				_, _ = writer.WriteString(fmt.Sprintf("      - Match: %-30s (Count: %d)\n", `"`+match+`"`, count))
			}
		}
	}
	_, _ = writer.WriteString("\n")
}

func runJSAnalysis(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	logger.Info("Starting JavaScript analysis", "input", inputFile)
	if !FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for JS analysis does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	jsURLs, err := GetJSURLsFromFile(inputFile) // This function needs logger too
	if err != nil {
		return err
	}
	if len(jsURLs) == 0 {
		logger.Warn("No JavaScript URLs found in input file, skipping JS analysis.", "file", inputFile)
		return nil
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

	for _, jsURL := range jsURLs {
		select {
		case <-ctx.Done():
			logger.Info("JS analysis cancelled by context", "error", ctx.Err())
			return ctx.Err()
		case concurrencyLimit <- struct{}{}:
			wg.Add(1)
			go func(urlStr string) {
				defer wg.Done()
				defer func() { <-concurrencyLimit }()
				processSingleJSURL(ctx, urlStr, writer, &muWriter, logger) // This function needs logger too
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
		findings := URLFindings{
			URL:       jsURL,
			Secrets:   smSecrets,
			Endpoints: smEndpoints,
		}
		WriteFindings(writer, mu, "SOURCEMAP", findings)
	}
}

type SourceMap struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

func analyzeSourceMap(jsURL string, content []byte, logger *slog.Logger) (allSecrets []Finding, allEndpoints []Finding) { // This function needs logger too
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

// runShuffleDNS executa o shuffledns para resolver e fazer bruteforce de subdomínios.
func runShuffleDNS(ctx context.Context, domain, wordlist, subdomainsFile, tempDir string, logger *slog.Logger) ([]string, error) {
	resolversFile := filepath.Join(tempDir, "redrecon_resolvers.txt")

	// Se o arquivo de resolvers não existir no diretório temporário, tenta gerá-lo.
	if !FileExistsAndIsNotEmpty(resolversFile) {
		logger.Warn("Resolvers file not found in temporary directory. Attempting to generate it...", "path", resolversFile)
		// Tenta gerar o arquivo de resolvers, mas com um timeout para não bloquear o fluxo.
		generateResolvers(resolversFile, logger)
	}

	hasInputSubs := FileExistsAndIsNotEmpty(subdomainsFile)
	hasWordlist := wordlist != "" && FileExistsAndIsNotEmpty(wordlist)

	if !hasInputSubs && !hasWordlist {
		logger.Warn("Both subdomain wordlist and input subdomains file are missing or empty, skipping shuffledns.", "wordlist", wordlist, "subdomains_file", subdomainsFile)
		return nil, nil
	}

	logger.Info("Executing external shuffledns command.", "domain", domain)

	var args []string
	// Prioriza o modo 'bruteforce' se uma wordlist for fornecida, pois ele também resolve.
	// Se apenas uma lista de subdomínios existir, usa o modo 'resolve'.
	if hasWordlist {
		logger.Info("Running shuffledns in 'bruteforce' mode using wordlist.", "wordlist", wordlist)
		args = []string{
			"-d", domain,
			"-w", wordlist,
			"-mode", "bruteforce",
			"-silent",
		}
		// Adiciona o arquivo de resolvers apenas se ele foi gerado com sucesso.
		if FileExistsAndIsNotEmpty(resolversFile) {
			args = append(args, "-r", resolversFile)
		}
		// Se também houver uma lista de subdomínios, adicione-a para resolução.
		if hasInputSubs {
			args = append(args, "-list", subdomainsFile)
		}
	} else if hasInputSubs { // Apenas a lista de subdomínios existe
		logger.Info("Running shuffledns in 'resolve' mode using existing subdomains list.", "subdomains_file", subdomainsFile)
		args = []string{
			"-d", domain,
			"-list", subdomainsFile,
			"-mode", "resolve",
			"-silent",
		}
		if FileExistsAndIsNotEmpty(resolversFile) {
			args = append(args, "-r", resolversFile)
		}
	}

	// Executa o comando e captura o stdout.
	out, err := ExecuteCommand(ctx, logger, "shuffledns", args...)
	if err != nil {
		return nil, err // O erro já vem formatado do executeCommand.
	}

	var foundSubdomains []string
	for _, line := range strings.Split(out, "\n") {
		if trimmedLine := strings.TrimSpace(line); trimmedLine != "" {
			foundSubdomains = append(foundSubdomains, trimmedLine)
		}
	}
	return foundSubdomains, nil
}

// generateResolvers tenta criar uma lista de resolvedores de DNS usando dnsvalidator.
// Esta função tem seu próprio timeout para não bloquear o processo principal.
func generateResolvers(outputFile string, logger *slog.Logger) {
	logger.Info("Using a built-in list of trusted public DNS resolvers.")

	// Lista de resolvedores públicos rápidos e confiáveis.
	// Isso é muito mais rápido e estável do que validar uma lista enorme a cada execução.
	resolvers := []string{
		"1.1.1.1",    // Cloudflare
		"1.0.0.1",    // Cloudflare
		"8.8.8.8",    // Google
		"8.8.4.4",    // Google
		"9.9.9.9",    // Quad9
		"149.112.112.112", // Quad9
		"208.67.222.222", // OpenDNS
		"208.67.220.220", // OpenDNS
	}

	content := strings.Join(resolvers, "\n")
	err := os.WriteFile(outputFile, []byte(content), 0644)

	if err != nil {
		logger.Error("Failed to write built-in resolvers file. shuffledns will use system resolvers.", "error", err)
		return
	}
	logger.Info("Successfully created resolvers file from built-in list.", "path", outputFile)
}

type FaviconResult struct {
	Host         string `json:"host"`
	FaviconURL   string `json:"favicon_url"`
	Murmur3Hash  string `json:"murmur3_hash"`
	ShodanSearch string `json:"shodan_search"`
}

func runFaviconHash(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	if !FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for favicon analysis does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	
	hosts, err := ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for favicon analysis: %w", err)
	}

	var allResults []FaviconResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)
	client := &http.Client{Timeout: 10 * time.Second}

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
			faviconURL := faviconURLs[0] // Use the first found URL

			req, err := http.NewRequestWithContext(ctx, "GET", faviconURL, nil)
			if err != nil {
				return
			}

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

			result := FaviconResult{
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
	c.SetClient(&http.Client{Timeout: 10 * time.Second})

	c.OnHTML("link[rel~='icon']", func(e *colly.HTMLElement) {
		href := e.Attr("href")
		absoluteURL := e.Request.AbsoluteURL(href)
		foundURLs = append(foundURLs, absoluteURL)
	})

	if err := c.Visit(hostURL); err != nil {
		return nil, err
	}
	c.Wait()

	return foundURLs, nil
}

type CVEResult struct {
	URL         string `json:"url"`
	Technology  string `json:"technology"`
	CVE_ID      string `json:"cve_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVSS_V3     string `json:"cvss_v3"`
}

type NVDResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID          string `json:"id"`
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

type HttpxTechInfo struct {
	URL  string   `json:"url"`
	Tech []string `json:"tech"`
}

// RunCVESearch procura por CVEs conhecidas com base nas tecnologias detectadas.
func RunCVESearch(ctx context.Context, techFile, outputFile string, logger *slog.Logger) error {
	if !FileExistsAndIsNotEmpty(techFile) {
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

	var allResults []CVEResult
	var mu sync.Mutex
	var wg sync.WaitGroup
	client := &http.Client{Timeout: 20 * time.Second}

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

			var nvdResp NVDResponse
			if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
				logger.Warn("Failed to decode NVD API response", "tech", t, "error", err)
				return
			}

			mu.Lock()
			for _, vuln := range nvdResp.Vulnerabilities {
				result := CVEResult{
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

func RunFfuf(ctx context.Context, inputFile, wordlist, outputDir string, rateLimit int, logger *slog.Logger) error {
	if !FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for ffuf does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	if wordlist == "" || !FileExistsAndIsNotEmpty(wordlist) {
		logger.Warn("Fuzzing wordlist not configured or file not found, skipping ffuf.", "file", wordlist)
		return nil // This function needs logger too
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create ffuf output directory: %w", err)
	}

	logger.Info("Executing external ffuf command. Ensure it's installed in your system's PATH.")

	hosts, err := ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for ffuf: %w", err)
	}

	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, host := range hosts {
		wg.Add(1)
		concurrencyLimit <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()
			
			sanitizedHost := SanitizeTargetForPath(h)
			hostOutputFile := filepath.Join(outputDir, fmt.Sprintf("%s.json", sanitizedHost))

			logger.Debug("Running ffuf scan", "host", h)
			args := []string{
				"-w", wordlist,
				"-u", h+"/FUZZ",
				"-o", hostOutputFile,
				"-of", "json",
				"-ac", // Ativa a autocalibração de filtros para ignorar lixo.
				"-noninteractive", // Garante que não haverá prompts.
				"-maxtime", "300", // Limita a execução a 5 minutos por host.
			}

			if rateLimit > 0 {
				logger.Info("Applying rate limit to ffuf.", "host", h, "rate", rateLimit)
				args = append(args, "-rate", fmt.Sprintf("%d", rateLimit))
			}

			cmd := exec.CommandContext(ctx, config.GetToolPath("ffuf"), args...)

			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			err := cmd.Run()
			if err != nil {
				logger.Warn("ffuf scan for host failed", "host", h, "error", err, "stderr", stderr.String())
			} // This function needs logger too
		}(host)
	}

	wg.Wait()

	return nil
}

func runDirsearch(ctx context.Context, inputFile, wordlist, outputDir string, rateLimit int, logger *slog.Logger) error {
	if !CommandExists("dirsearch") {
		logger.Warn("dirsearch is not installed or not executable, skipping.", "tool", "dirsearch", "help", "Install with: pip3 install dirsearch")
		return nil // Não é um erro fatal, apenas pula a ferramenta.
	}
	if !FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for dirsearch does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	if wordlist == "" || !FileExistsAndIsNotEmpty(wordlist) {
		logger.Warn("Fuzzing wordlist not configured or file not found, skipping dirsearch.", "file", wordlist)
		return nil
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create dirsearch output directory: %w", err)
	}

	hosts, err := ReadLines(inputFile)
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

			sanitizedHost := SanitizeTargetForPath(h)
			// dirsearch lida com a extensão do arquivo, então apenas fornecemos o caminho base.
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
				// dirsearch usa --rate
				logger.Info("Applying rate limit to dirsearch.", "host", h, "rate", rateLimit)
				args = append(args, fmt.Sprintf("--rate=%d", rateLimit))
			}

			// dirsearch é um script python, então pode ser necessário chamá-lo com 'python3'
			// A função GetToolPath deve retornar o executável correto.
			if _, err := ExecuteCommand(ctx, logger, "dirsearch", args...); err != nil {
				logger.Warn("dirsearch scan for host failed", "host", h, "error", err)
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func runWafw00f(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	if !CommandExists("wafw00f") {
		logger.Error("wafw00f is not installed or not executable. Please check your PATH and permissions.", "tool", "wafw00f")
		return fmt.Errorf("wafw00f not found or not executable")
	}
	if !FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for wafw00f does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	logger.Info("Starting wafw00f to detect Web Application Firewalls", "input", inputFile)

	args := []string{
		"-i", inputFile,
		"-o", outputFile,
		"-f", "json", // Formato de saída JSON para fácil parsing futuro
		"-a", // Procura por todos os WAFs, não para no primeiro encontrado
	}

	if _, err := ExecuteCommand(ctx, logger, "wafw00f", args...); err != nil {
		// wafw00f pode falhar em alguns hosts, mas não queremos que isso quebre a cadeia.
		logger.Warn("wafw00f execution finished with an error, but this might be acceptable.", "error", err)
	}

	return nil
}

func runPortScan(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	if !FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for port scan does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	// Extrai apenas os hostnames, pois o naabu não lida bem com URLs completas.
	hosts, err := ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for port scan: %w", err)
	}
	hostnames := make(map[string]struct{})
	for _, h := range hosts {
		if u, err := url.Parse(h); err == nil {
			hostnames[u.Hostname()] = struct{}{}
		}
	}

	var uniqueHostnames []string
	for hn := range hostnames {
		uniqueHostnames = append(uniqueHostnames, hn)
	}

	logger.Info("Starting port scan on live hosts", "host_count", len(uniqueHostnames))
	args := []string{"-host", strings.Join(uniqueHostnames, ","), "-o", outputFile, "-silent", "-top-ports", "1000"}

	_, err = ExecuteCommand(ctx, logger, "naabu", args...)
	return err // Retorna o erro para ser tratado pela etapa.
}

func getCSPDomains(ctx context.Context, liveSubdomainsFile, mainTarget string, logger *slog.Logger) ([]string, error) {
	if !FileExistsAndIsNotEmpty(liveSubdomainsFile) {
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
	client := &http.Client{Timeout: 10 * time.Second}
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
	if !FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Warn("Input file for HTML analysis does not exist or is empty, skipping.", "file", state.liveSubdomainsFile)
		return nil
	}
	
	hosts, err := ReadLines(state.liveSubdomainsFile)
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

	// Diretório para salvar os arquivos HTML para análise posterior.
	htmlFilesPath := filepath.Join(state.resultsPath, "html_files")
	if err := os.MkdirAll(htmlFilesPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory for HTML files: %w", err)
	}

	// --- Etapa 1: Coletar e salvar os arquivos HTML ---
	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(1), // Profundidade 1 é suficiente para a página inicial de cada host.
	)

	_ = c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: config.Cfg.Engine.MaxParallelTasks,
		Delay:       50 * time.Millisecond,
	})

	c.OnResponse(func(r *colly.Response) {
		sanitizedFilename := SanitizeTargetForPath(r.Request.URL.String()) + ".html"
		filePath := filepath.Join(htmlFilesPath, sanitizedFilename)
		if err := os.WriteFile(filePath, r.Body, 0644); err != nil {
			state.logger.Error("Failed to save HTML file", "path", filePath, "error", err)
		} else {
			state.logger.Debug("Saved HTML file for analysis", "path", filePath)
		}
	})

	for _, host := range hosts {
		_ = c.Visit(host)
	}
	c.Wait()
	state.logger.Info("HTML file collection finished. Starting analysis.")

	// --- Etapa 2: Analisar os arquivos HTML salvos ---
	return filepath.Walk(htmlFilesPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".html") {
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				state.logger.Warn("Failed to read saved HTML file for analysis", "path", path, "error", readErr)
				return nil // Continua para o próximo arquivo
			}

			htmlContent := string(content)
			secrets, endpoints := AnalyzeContentForPatterns(htmlContent)

			if len(secrets) > 0 || len(endpoints) > 0 {
				mu.Lock()
				defer mu.Unlock()
				_, _ = writer.WriteString(fmt.Sprintf("--- Findings in HTML from file: %s ---\n", path))
				if len(secrets) > 0 {
					_, _ = writer.WriteString(fmt.Sprintf("  [SECRETS] %v\n", secrets))
				}
				if len(endpoints) > 0 {
					_, _ = writer.WriteString(fmt.Sprintf("  [ENDPOINTS] %v\n", endpoints))
				}
				_, _ = writer.WriteString("\n")
			}
		}
		return nil
	})
}

func generateReconSummary(state *reconState) (string, []string, error) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **Recon Summary for: %s**\n\n", state.target))

	// Helper to count lines in a file
	countLines := func(path string) int {
		if !FileExistsAndIsNotEmpty(path) {
			return 0
		}
		file, err := os.Open(path)
		if err != nil {
			return 0
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		count := 0
		for scanner.Scan() {
			count++
		}
		return count
	}

	summary.WriteString(fmt.Sprintf("• **Subdomains Found:** %d\n", countLines(state.subdomainsFile)))
	summary.WriteString(fmt.Sprintf("• **Live Hosts:** %d\n", countLines(state.liveSubdomainsFile)))
	summary.WriteString(fmt.Sprintf("• **URLs Discovered:** %d\n", countLines(state.urlsFile)))

	summary.WriteString(fmt.Sprintf("\n*Full results are saved in:* `%s`", state.resultsPath)) // This function needs logger too

	// Lista de arquivos de resultado para anexar
	resultFiles := []string{
		state.subdomainsFile,
		state.liveSubdomainsFile,
		state.urlsFile,
		state.jsFindingsFile,
		state.htmlFindingsFile,
	}

	return summary.String(), resultFiles, nil
}

// CountLines é uma função auxiliar para contar linhas em um arquivo.
func CountLines(path string) int {
	if !FileExistsAndIsNotEmpty(path) {
		return 0
	}
	file, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() { count++ }
	return count
}
