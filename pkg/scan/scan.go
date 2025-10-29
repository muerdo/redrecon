package scan

import (
	"encoding/json"
	"bufio"
	"context"
	"fmt"
	"regexp"
	"log/slog"
	url_pkg "net/url"
	"os"
	"path/filepath"

	"strings"
	"sync"

	"redrecon/internal/config"
	"redrecon/pkg/recon" // Usado para SanitizeTargetForPath e fileExistsAndIsNotEmpty
)

// executeCommand é uma função auxiliar para executar comandos externos.
// Ela delega a chamada para a função centralizada no pacote recon.
func executeCommand(ctx context.Context, logger *slog.Logger, toolName string, args ...string) (string, error) {
	// Reutiliza a função robusta do pacote recon para consistência.
	return recon.ExecuteCommand(ctx, logger, toolName, args...)
}

// scanState armazena o estado e os caminhos para uma operação de varredura.
type scanState struct {
	ctx                context.Context
	target             string
	resultsPath        string // Caminho base para os resultados do alvo
	liveSubdomainsFile string
	wafResultsFile     string // Caminho para o arquivo de resultados do WAF
	urlsFile           string
	techFile           string
	vulnerabilityFile  string
	nucleiScanFile     string
	cveScanFile        string
	niktoScanFile      string
	owaspScanFile      string
	bbotScanFile       string
	apiFuzzFile        string
	tempDir            string // Diretório temporário para esta execução de scan
	logger             *slog.Logger
	wafMap             map[string]string // Mapeia host -> nome do WAF
}

type scanStep func(state *scanState) error

// StartScan inicia o fluxo de trabalho de varredura de vulnerabilidades para um alvo.
func StartScan(taskIdentifier string, target string, skipSteps, onlySteps []string, logger *slog.Logger) (string, []string, error) {
	logger.Info("Starting vulnerability scan process", "target", target)

	sanitizedTaskIdentifier := recon.SanitizeTargetForPath(taskIdentifier)
	// O scan lê de 'recon' e escreve em 'scan' para manter a separação.
	reconResultsPath := filepath.Join("results", sanitizedTaskIdentifier, "recon")
	scanResultsPath := filepath.Join("results", sanitizedTaskIdentifier, "scan")
	
	// Verifica se o diretório de resultados do 'recon' existe e tem conteúdo útil.
	// O scan depende dos artefatos gerados pelo recon.
	liveSubdomainsFile := filepath.Join(reconResultsPath, "live_subdomains.txt")
	urlsFile := filepath.Join(reconResultsPath, "urls.txt")
	if !recon.FileExistsAndIsNotEmpty(liveSubdomainsFile) && !recon.FileExistsAndIsNotEmpty(urlsFile) {
		errMsg := fmt.Sprintf("recon results not found or are empty for target '%s'. Please run 'recon' command first.", target)
		logger.Error(errMsg, "checked_path", reconResultsPath)
		return "", nil, fmt.Errorf(errMsg)
	}

	if err := os.MkdirAll(scanResultsPath, 0755); err != nil {
		logger.Error("Failed to create scan directory", "path", scanResultsPath, "error", err)
		return "", nil, fmt.Errorf("could not create directory %s: %w", scanResultsPath, err)
	}

	// Cria um diretório temporário dentro da pasta de resultados do alvo para esta execução específica do scan.
	tempDir := filepath.Join(scanResultsPath, "tmp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create temporary directory for scan: %w", err)
	}

	state := &scanState{
		ctx:                context.Background(),
		target:             target,
		resultsPath:        scanResultsPath,
		logger:             logger,
		wafResultsFile:     filepath.Join(reconResultsPath, "waf_results.json"),
		liveSubdomainsFile: liveSubdomainsFile,
		urlsFile:           urlsFile,
		techFile:           filepath.Join(reconResultsPath, "httpx_tech.json"),
		vulnerabilityFile:  filepath.Join(scanResultsPath, "vulnerability_findings.txt"),
		nucleiScanFile:     filepath.Join(scanResultsPath, "nuclei_scan.txt"),
		cveScanFile:        filepath.Join(scanResultsPath, "cve_results.json"),
		niktoScanFile:      filepath.Join(scanResultsPath, "nikto_scan.txt"),
		owaspScanFile:      filepath.Join(scanResultsPath, "owasp_scan.txt"),
		bbotScanFile:       filepath.Join(scanResultsPath, "bbot_scan.json"),
		apiFuzzFile:        filepath.Join(scanResultsPath, "apifuzz_results.json"),
		tempDir:            tempDir,
		wafMap:             make(map[string]string),
	}

	// Carrega os resultados do WAF no estado do scan para uso dinâmico.
	if err := loadWAFResults(state); err != nil {
		// Não é um erro fatal, apenas um aviso. O scan continuará sem evasão dinâmica.
		logger.Warn("Could not load WAF results, dynamic evasion will not be available.", "error", err)
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	workflow := map[string]scanStep{
		"vulntests": stepRunVulnerabilityTests,
		"nuclei":    stepRunNucleiScan,
		"cvesearch": stepRunCVESearch,
		"owasp":     stepRunOWASPTests,
		"nikto":     stepRunNikto,
		"bbot":      stepRunBBot,
		"apifuzz":   stepRunAPIFuzzing,
	}

	var executionOrder []string

	// Se a flag --only for usada, a ordem de execução será apenas os passos especificados.
	if len(onlySteps) > 0 {
		for _, step := range onlySteps {
			if _, ok := workflow[step]; !ok {
				return "", nil, fmt.Errorf("invalid step specified in --only flag: %s", step)
			}
		}
		executionOrder = onlySteps
		skipSet = make(map[string]struct{}) // Ignora qualquer flag --skip se --only for usada
	} else {
		// Ordem de execução padrão se --only não for usada.
		executionOrder = []string{"vulntests", "nuclei", "cvesearch", "owasp", "nikto", "bbot", "apifuzz"}
	}

	logger.Info("Starting vulnerability scan tasks.")

	var wg sync.WaitGroup
	// Limita o número de ferramentas pesadas rodando ao mesmo tempo.
	// O valor pode ser ajustado na configuração se necessário.
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)
	errChan := make(chan error, len(executionOrder))

	for _, stepName := range executionOrder {
		if _, shouldSkip := skipSet[stepName]; shouldSkip {
			state.logger.Warn("Skipping step as requested", "step", stepName)
			continue
		}

		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			logger.Info(fmt.Sprintf("Starting scan step: %s", name))
			concurrencyLimit <- struct{}{} // Adquire um slot de concorrência
			defer func() { <-concurrencyLimit }() // Libera o slot

			stepFunc := workflow[name]
			if err := stepFunc(state); err != nil {
				logger.Error("A scan step failed", "step", name, "error", err)
				errChan <- fmt.Errorf("step %s failed: %w", name, err)
			}
		}(stepName)
	}

	wg.Wait()
	close(errChan)

	logger.Info("Vulnerability scan process completed.")
	// Podemos decidir no futuro se queremos agregar os erros de `errChan`. Por enquanto, eles já são logados.
	return generateScanSummary(state)
}

// WAFResult define a estrutura de uma entrada no arquivo de resultados do wafw00f.
type WAFResult struct {
	URL      string `json:"url"`
	Firewall string `json:"firewall"`
	Detected bool   `json:"detected"`
}

// loadWAFResults lê o arquivo waf_results.json e popula o wafMap no estado do scan.
func loadWAFResults(s *scanState) error {
	if !config.Cfg.Engine.WAF.Enabled || !recon.FileExistsAndIsNotEmpty(s.wafResultsFile) {
		s.logger.Debug("WAF detection disabled or results file not found, skipping loading.", "file", s.wafResultsFile)
		return nil // WAF desabilitado ou arquivo não existe, nada a fazer.
	}

	file, err := os.Open(s.wafResultsFile)
	if err != nil {
		return fmt.Errorf("failed to open WAF results file: %w", err)
	}
	defer file.Close()

	var wafResults []WAFResult
	if err := json.NewDecoder(file).Decode(&wafResults); err != nil {
		// O arquivo pode não ser um JSON válido se o wafw00f falhar.
		s.logger.Warn("Failed to decode WAF results JSON, file might be invalid.", "file", s.wafResultsFile, "error", err)
		return nil
	}

	for _, result := range wafResults {
		if result.Detected && result.Firewall != "None" && result.Firewall != "" {
			// Normaliza a URL para hostname para consistência
			parsedURL, err := url_pkg.Parse(result.URL)
			if err == nil {
				// Armazena o nome do WAF em minúsculas para facilitar a correspondência de perfis.
				hostname := parsedURL.Hostname()
				wafName := strings.ToLower(result.Firewall)
				s.wafMap[hostname] = wafName
				s.logger.Debug("Mapped host to WAF", "host", hostname, "waf", wafName)
			}
		}
	}

	if len(s.wafMap) > 0 {
		s.logger.Info("Successfully loaded WAF detection results.", "detected_count", len(s.wafMap))
	} else {
		s.logger.Info("WAF results file processed, but no specific WAFs were detected.")
	}

	return nil
}

func stepRunVulnerabilityTests(s *scanState) error {
	s.logger.Info("--- Starting: Basic Vulnerability Tests (XSS, SQLi) ---")
	if !recon.FileExistsAndIsNotEmpty(s.urlsFile) {
		s.logger.Warn("Input file for vulnerability tests is empty, skipping.", "file", s.urlsFile)
		return nil
	}

	xssPayloads := `"><script>alert('XSS')</script>,'"--> </style></scRipt><scRipt>alert('XSS')</scRipt>`
	args := []string{
		"-l", s.urlsFile, "-o", s.vulnerabilityFile, "-silent", "-no-color",
		"-threads", fmt.Sprintf("%d", config.Cfg.Engine.MaxParallelTasks), "-tmp-dir", s.tempDir,
		"-timeout", "10", "-random-agent", "-xss", "-xss-payload", xssPayloads,
		"-sqli", "-unsafe", "-crlf", "-ssti",
	}

	if _, err := executeCommand(s.ctx, s.logger, "httpx", args...); err != nil {
		// httpx pode retornar um código de saída diferente de zero se não conseguir se conectar a nenhuma URL.
		// Tratamos isso como um aviso em vez de um erro fatal para não interromper o fluxo do 'chain'.
		s.logger.Warn("httpx (vulnerability) step finished with a non-zero exit code. This can happen if no URLs were reachable.", "error", err)
	}

	if recon.FileExistsAndIsNotEmpty(s.vulnerabilityFile) {
		s.logger.Info("Vulnerability testing completed", "output_file", s.vulnerabilityFile)
	}
	return nil
}

func stepRunNucleiScan(s *scanState) error {
	s.logger.Info("--- Starting: Vulnerability Scanning (Nuclei) ---")
	err := runNucleiScan(s, config.Cfg.Recon.Nuclei.Templates)
	if err != nil {
		return err
	}
	if recon.FileExistsAndIsNotEmpty(s.nucleiScanFile) {
		s.logger.Info("Nuclei scan completed", "output_file", s.nucleiScanFile)
	}
	return nil
}

func stepRunCVESearch(s *scanState) error {
	s.logger.Info("--- Starting: Known Vulnerability Search (CVE API) ---")
	err := runCVESearch(s.ctx, s.techFile, s.cveScanFile, s.logger)
	if err != nil {
		return err
	}
	if recon.FileExistsAndIsNotEmpty(s.cveScanFile) {
		s.logger.Info("CVE search completed", "output_file", s.cveScanFile)
	}
	return nil
}

func stepRunOWASPTests(s *scanState) error {
	s.logger.Info("--- Starting: OWASP Top 10 Intrusion Tests (Nuclei) ---")
	owaspTemplates := config.Cfg.Recon.Nuclei.OWASPTemplates
	if len(owaspTemplates) == 0 {
		s.logger.Warn("No specific OWASP Top 10 templates configured. Using a default set.")
		owaspTemplates = []string{
			"http/vulnerabilities/access-control/", "http/vulnerabilities/command-injection/",
			"http/vulnerabilities/crlf-injection/", "http/vulnerabilities/file-inclusion/",
			"http/vulnerabilities/open-redirect/", "http/vulnerabilities/prototype-pollution/",
			"http/vulnerabilities/rce/", "http/vulnerabilities/ssrf/",
			"http/vulnerabilities/sql-injection/", "http/vulnerabilities/xss/",
			"http/miscellaneous/exposed-panels/", "http/miscellaneous/default-credentials/",
			"http/miscellaneous/insecure-configurations/", "http/technologies/outdated-versions/",
		}
	}
	err := runNucleiScan(s, owaspTemplates)
	if err != nil {
		return err
	}
	if recon.FileExistsAndIsNotEmpty(s.owaspScanFile) {
		s.logger.Info("OWASP Top 10 tests completed", "output_file", s.owaspScanFile)
	} else {
		s.logger.Info("OWASP Top 10 tests completed with no findings.")
	}
	return nil
}

func stepRunNikto(s *scanState) error {
	s.logger.Info("--- Starting: Web Server Scanning (Nikto) ---")
	err := runNikto(s)
	if err != nil {
		return err
	}
	if recon.FileExistsAndIsNotEmpty(s.niktoScanFile) {
		s.logger.Info("Nikto scan completed", "output_file", s.niktoScanFile)
	}
	return nil
}

func stepRunBBot(s *scanState) error {
	s.logger.Info("--- Starting: Full-scope Recon (BBot) ---")
	err := runBBot(s.ctx, s.target, s.bbotScanFile, s.tempDir, s.logger)
	if err != nil {
		return err
	}
	if recon.FileExistsAndIsNotEmpty(s.bbotScanFile) {
		s.logger.Info("BBot scan completed", "output_file", s.bbotScanFile)
	}
	return nil
}

func stepRunAPIFuzzing(s *scanState) error {
	s.logger.Info("--- Starting: API Endpoint Fuzzing (ffuf) ---")

	// 1. Obter a lista de URLs de JavaScript do arquivo urls.txt
	jsURLs, err := recon.GetJSURLsFromFile(s.urlsFile)
	if err != nil {
		return fmt.Errorf("failed to get JS URLs for API fuzzing: %w", err)
	}
	if len(jsURLs) == 0 {
		s.logger.Info("No JavaScript URLs found in recon results, skipping API fuzzing.")
		return nil
	}

	// 2. Definir um conjunto mais robusto de regex para extrair endpoints
	endpointPatterns := []*regexp.Regexp{
		regexp.MustCompile(`['"](/[\w\-/._~:?#\[\]@!$&'()*+,;=]+){2,}['"]`), // Caminhos de URL genéricos com pelo menos 2 segmentos
		regexp.MustCompile(`['"](/api(/[\w\-/._~:?#\[\]@!$&'()*+,;=]+)*)['"]`), // Caminhos que começam com /api
		regexp.MustCompile(`['"](https?://[\w\-./?#&%=]+)['"]`),               // URLs completas
	}

	endpoints := make(map[string]struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	// 3. Baixar e analisar cada arquivo JS em paralelo
	for _, jsURL := range jsURLs {
		wg.Add(1)
		concurrencyLimit <- struct{}{}
		go func(url string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			content, err := recon.DownloadContent(url)
			if err != nil {
				s.logger.Debug("Failed to download JS for API fuzzing", "url", url, "error", err)
				return
			}

			for _, pattern := range endpointPatterns {
				matches := pattern.FindAllStringSubmatch(string(content), -1)
				mu.Lock()
				for _, match := range matches {
					// Extrai o caminho limpo, removendo aspas e barras iniciais
					endpointPath := strings.Trim(match[1], `"'`) // Usa o grupo de captura 1
					if u, err := url_pkg.Parse(endpointPath); err == nil {
						path := strings.TrimPrefix(u.Path, "/")
						// Validação mais forte: deve ser um caminho, não ter extensões comuns de arquivo estático e ter um comprimento razoável.
						if path != "" && len(path) > 3 && !strings.ContainsAny(path, ".js.css.html.png.jpg.svg") {
							endpoints[path] = struct{}{}
						}
					}
				}
				mu.Unlock()
			}
		}(jsURL)
	}
	wg.Wait()

	if len(endpoints) == 0 {
		s.logger.Info("No API endpoints found in JavaScript files, skipping API fuzzing.")
		return nil
	}

	// 4. Cria um arquivo de wordlist temporário com os endpoints encontrados
	// Usa o diretório temporário do scan para manter tudo contido.
	endpointListPath := filepath.Join(s.tempDir, "api_endpoints.txt")
	endpointListFile, err := os.Create(endpointListPath)
	if err != nil {
		return fmt.Errorf("failed to create temporary endpoint wordlist: %w", err)
	}
	defer os.Remove(endpointListFile.Name())

	var endpointContent strings.Builder
	for ep := range endpoints {
		endpointContent.WriteString(ep + "\n")
	}
	if _, err := endpointListFile.WriteString(endpointContent.String()); err != nil {
		return fmt.Errorf("failed to write to temporary endpoint wordlist: %w", err)
	}
	endpointListFile.Close() // Fecha o arquivo para que o ffuf possa lê-lo

	s.logger.Info("Found endpoints to test", "count", len(endpoints))

	// Adiciona uma verificação explícita para o liveSubdomainsFile, que é necessário para o ffuf.
	if !recon.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Live subdomains file does not exist or is empty, skipping API fuzzing.", "file", s.liveSubdomainsFile)
		return nil
	}

	// 5. Usa a função de fuzzing do recon com a nova wordlist
	// Para o fuzzing de API, aplicamos uma lógica de evasão de WAF baseada no perfil padrão,
	// pois o ffuf será executado em múltiplos hosts.
	var ffufRateLimit int
	if config.Cfg.Engine.WAF.Enabled {
		profile := config.Cfg.Engine.WAF.DefaultProfile
		ffufRateLimit = profile.RateLimit
		s.logger.Info("Applying default WAF rate limit for API Fuzzing (ffuf).", "rate_limit", ffufRateLimit)
	}

	// A função RunFfuf agora aceita um rateLimit.
	return recon.RunFfuf(s.ctx, s.liveSubdomainsFile, endpointListFile.Name(), s.apiFuzzFile, ffufRateLimit, s.logger)
}

func runNucleiScan(s *scanState, templates []string) error {
	if !recon.CommandExists("nuclei") {
		s.logger.Error("nuclei command not found in PATH. Please install it to proceed.", "tool", "nuclei")
		return fmt.Errorf("nuclei not found in PATH")
	}

	if !recon.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Input file for Nuclei does not exist or is empty, skipping.", "file", s.liveSubdomainsFile)
		return nil
	}
	if len(templates) == 0 {
		s.logger.Warn("No Nuclei templates specified, skipping scan.")
		return nil
	}

	// 1. Agrupar hosts por WAF detectado
	groupedHosts := make(map[string][]string) // Chave: nome do WAF ou "none"
	allHosts, err := recon.ReadLines(s.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for Nuclei: %w", err)
	}

	for _, host := range allHosts {
		parsedURL, err := url_pkg.Parse(host)
		if err != nil {
			continue
		}
		hostname := parsedURL.Hostname()

		wafName, found := s.wafMap[hostname]
		if !found || !config.Cfg.Engine.WAF.Enabled {
			wafName = "none" // Agrupa hosts sem WAF ou se a evasão estiver desabilitada
		}
		groupedHosts[wafName] = append(groupedHosts[wafName], host)
	}

	// 2. Executar Nuclei para cada grupo de hosts
	for wafName, hosts := range groupedHosts {
		if len(hosts) == 0 {
			continue
		}

		// Cria um arquivo temporário para a lista de hosts deste grupo
		tempInputFile, err := os.CreateTemp(s.tempDir, fmt.Sprintf("nuclei_hosts_%s_*.txt", wafName))
		if err != nil {
			s.logger.Error("Failed to create temporary host file for Nuclei group", "group", wafName, "error", err)
			continue
		}
		defer os.Remove(tempInputFile.Name())

		if _, err := tempInputFile.WriteString(strings.Join(hosts, "\n")); err != nil {
			s.logger.Error("Failed to write to temporary host file", "group", wafName, "error", err)
			tempInputFile.Close()
			continue
		}
		tempInputFile.Close()

		// 3. Montar os argumentos do Nuclei com o perfil de evasão correto
		args := []string{
			"-l", tempInputFile.Name(),
			"-o", s.nucleiScanFile, // Anexa a saída ao mesmo arquivo de resultados
			"-silent", "-no-color",
			"-retries", "2", "-timeout", "10",
			"-tmp-dir", s.tempDir,
		}

		// Adiciona os templates
		for _, t := range templates {
			args = append(args, "-t", t)
		}

		// Aplica o perfil de evasão
		if wafName == "none" {
			s.logger.Info("Running Nuclei for hosts with no WAF detected.", "host_count", len(hosts))
			// Usa parâmetros de alta concorrência para hosts sem WAF
			args = append(args, "-bulk-size", "50", "-c", "25")
		} else {
			profile, ok := config.Cfg.Engine.WAF.Profiles[wafName]
			if !ok {
				profile = config.Cfg.Engine.WAF.DefaultProfile
				s.logger.Info("Running Nuclei with default WAF profile.", "waf", wafName, "host_count", len(hosts))
			} else {
				s.logger.Info("Running Nuclei with specific WAF profile.", "waf", wafName, "host_count", len(hosts))
			}

			// Aplica os limites do perfil
			if profile.RateLimit > 0 {
				args = append(args, "-rate-limit", fmt.Sprintf("%d", profile.RateLimit))
			}
			if profile.Concurrency > 0 {
				// Nuclei usa '-c' para concorrência
				args = append(args, "-c", fmt.Sprintf("%d", profile.Concurrency))
			}
			if profile.ProxyFile != "" && recon.FileExistsAndIsNotEmpty(profile.ProxyFile) {
				args = append(args, "-proxy", profile.ProxyFile)
			}
		}

		// 4. Executar o comando
		if _, err := executeCommand(s.ctx, s.logger, "nuclei", args...); err != nil {
			s.logger.Warn("Nuclei scan for group finished with a non-zero exit code. This is often normal.", "group", wafName, "error", err)
		}
	}

	return nil
}

func runNikto(s *scanState) error {
	if !recon.CommandExists("nikto") {
		s.logger.Error("nikto command not found in PATH. Please install it to proceed.", "tool", "nikto")
		return fmt.Errorf("nikto not found in PATH")
	}

	if !recon.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Input file for Nikto does not exist or is empty, skipping.", "file", s.liveSubdomainsFile)
		return nil
	}

	s.logger.Info("Executing external nikto command in parallel.")
	hosts, err := recon.ReadLines(s.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for Nikto: %w", err)
	}

	outputFileHandle, err := os.OpenFile(s.niktoScanFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open nikto output file: %w", err)
	}
	defer func() {
		if err := outputFileHandle.Close(); err != nil {
			s.logger.Error("Failed to close nikto output file", "path", s.niktoScanFile, "error", err)
		}
	}()

	var wg sync.WaitGroup
	var mu sync.Mutex
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, host := range hosts {
		select {
		case <-s.ctx.Done():
			return s.ctx.Err()
		case concurrencyLimit <- struct{}{}:
			wg.Add(1)
			go func(h string) {
				defer wg.Done()
				defer func() { <-concurrencyLimit }()
				s.logger.Debug("Running Nikto scan", "host", h)
				parsedURL, err := url_pkg.Parse(h)
				if err != nil {
					s.logger.Warn("Failed to parse host URL for Nikto, skipping", "host", h, "error", err)
					return
				}
				// O argumento '-Format' foi removido. Nikto agora imprimirá para stdout,
				// que é capturado pelo `stdoutBuf`. O '-Format' requer um argumento '-o'
				// que não estamos usando aqui, causando o erro.
				// Tuning: 1 (Interesting File), 2 (Misconfiguration), 3 (Information Disclosure),
				// 4 (Injection), 5 (Remote File Retrieval), b (Software Identification).
				// Maxtime: Evita que o scan fique preso em um único host.				
				args := []string{"-h", parsedURL.Hostname(), "-Tuning", "1,2,3,4,5,b", "-maxtime", "10m"}

				// Lógica de evasão de WAF dinâmica para Nikto
				if wafName, found := s.wafMap[parsedURL.Hostname()]; found {
					profile, ok := config.Cfg.Engine.WAF.Profiles[wafName]
					if !ok {
						profile = config.Cfg.Engine.WAF.DefaultProfile // Usa o padrão se não houver perfil específico
						s.logger.Debug("No specific WAF profile found, using default.", "waf", wafName)
					}

					// Nikto usa -Pause em segundos (float) entre os testes.
					// O inverso do rate_limit é um bom começo.
					if profile.RateLimit > 0 {
						pauseSeconds := 1.0 / float64(profile.RateLimit)
						args = append(args, "-Pause", fmt.Sprintf("%.2f", pauseSeconds))
						s.logger.Info("Applying dynamic WAF evasion for Nikto.", "host", h, "waf", wafName, "pause", pauseSeconds)
					}
				} else if config.Cfg.Engine.WAF.Enabled {
					s.logger.Debug("WAF evasion enabled, but no WAF detected for this host. Running Nikto at normal speed.", "host", h)
				}
				
				if parsedURL.Scheme == "https" {
					args = append(args, "-ssl")
				}
				if port := parsedURL.Port(); port != "" {
					args = append(args, "-p", port)
				}

				// A função executeCommand agora lida com o diretório e captura de saída.
				// Nikto é executado no diretório temporário para evitar que ele crie arquivos em locais inesperados.
				stdout, err := executeCommand(s.ctx, s.logger, "nikto", args...)
				if err != nil {
					s.logger.Warn("Nikto scan for host completed with a non-zero exit code. This can be normal.", "host", h, "error", err)
				}

				mu.Lock()
				defer mu.Unlock()
				if len(stdout) > 0 {
					_, _ = outputFileHandle.WriteString(fmt.Sprintf("--- Nikto Scan for %s ---\n%s\n", h, stdout))
				}
			}(host)
		}
	}
	wg.Wait()
	return nil
}

func runBBot(ctx context.Context, target, outputFile, tempDir string, logger *slog.Logger) error {
	if !recon.CommandExists("bbot") {
		logger.Error("bbot command not found in PATH. Please install it to proceed.", "tool", "bbot")
		return fmt.Errorf("bbot not found in PATH")
	}

	logger.Info("Executing external bbot command.")
	preset := config.Cfg.Recon.BBot.Profile
	if preset == "" {
		preset = "recon-light" // Perfil padrão
	}
	logger.Info("Using bbot preset", "preset", preset)

	args := []string{
		"-t", target,
		"-p", preset,
		"-o", outputFile,
		"--temp-dir", tempDir,
		"-om", "json",
		"-y", "-f",
	}
	if _, err := executeCommand(ctx, logger, "bbot", args...); err != nil {
		return fmt.Errorf("bbot execution failed: %w", err)
	}

	return nil
}

func runCVESearch(ctx context.Context, techFile, outputFile string, logger *slog.Logger) error {
	// Esta função é complexa e depende de structs agora localizadas no pacote `types`.
	// A lógica permanece no pacote `recon` para evitar duplicação de código.
	// Por simplicidade, vamos chamar a função pública do pacote recon.
	return recon.RunCVESearch(ctx, techFile, outputFile, logger)
}

func generateScanSummary(state *scanState) (string, []string, error) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **Scan Summary for: %s**\n\n", state.target))

	countLines := func(path string) int {
		if !recon.FileExistsAndIsNotEmpty(path) {
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

	summary.WriteString(fmt.Sprintf("• **Nuclei Findings:** %d\n", countLines(state.nucleiScanFile)))
	summary.WriteString(fmt.Sprintf("• **OWASP Top 10 Findings:** %d\n", countLines(state.owaspScanFile)))
	summary.WriteString(fmt.Sprintf("• **Basic Vulnerabilities (XSS/SQLi):** %d\n", countLines(state.vulnerabilityFile)))
	summary.WriteString(fmt.Sprintf("• **Known CVEs Found:** %d\n", countLines(state.cveScanFile)))

	summary.WriteString(fmt.Sprintf("\n*Full scan results are saved in:* `%s`", state.resultsPath))

	resultFiles := []string{
		state.nucleiScanFile,
		state.cveScanFile,
		state.owaspScanFile,
		state.vulnerabilityFile,
		state.niktoScanFile,
		state.bbotScanFile,
		state.apiFuzzFile,
	}

	return summary.String(), resultFiles, nil
}