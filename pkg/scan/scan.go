package scan

import (
	"bufio"
	"encoding/json"
	"context"
	"fmt"
	"regexp"
	"log/slog"
	url_pkg "net/url"
	"os"
	"path/filepath"

	"strings"
	"sync"

	"redrecon/pkg/analysis"
	"redrecon/internal/config"
	"redrecon/pkg/utils"
	"redrecon/pkg/types"
	"redrecon/pkg/tools"
	"redrecon/pkg/recon"
)

func executeCommand(ctx context.Context, logger *slog.Logger, toolName string, args ...string) (string, error) {
	return utils.ExecuteCommand(ctx, logger, toolName, args...)
}

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
	dalfoxScanFile     string
	paramSpiderFile    string
	owaspScanFile      string
	bbotScanFile       string
	apiFuzzFile        string

	parsedNucleiFindings []types.NucleiFinding
	parsedHttpxVulnFindings []analysis.HttpxVulnerabilityFinding
	parsedNiktoFindings []analysis.NiktoFinding
	parsedFfufFindings []analysis.FfufFinding
	parsedDirsearchFindings []analysis.DirsearchFinding
	parsedCVEFindings []types.CVEResult

	tempDir            string
	logger             *slog.Logger
	wafMap             map[string]string
}

type scanStep func(state *scanState) error

func StartScan(ctx context.Context, taskIdentifier string, inputFile string, skipSteps, onlySteps []string, isAggressive, isInteractive bool, logger *slog.Logger) (string, []string, error) {
	logger.Info("Starting vulnerability scan process", "task", taskIdentifier)

	sanitizedTaskIdentifier := utils.SanitizeTargetForPath(taskIdentifier)
	reconResultsPath := filepath.Join("results", sanitizedTaskIdentifier, "recon")
	scanResultsPath := filepath.Join("results", sanitizedTaskIdentifier, "scan")

	var initialTargetsFile string

	if inputFile != "" {
		if !utils.FileExistsAndIsNotEmpty(inputFile) {
			return "", nil, fmt.Errorf("input file provided but not found or is empty: %s", inputFile)
		}
		logger.Info("Using provided input file for scan targets", "file", inputFile)
		initialTargetsFile = inputFile
	} else {
		liveSubdomainsFile := filepath.Join(reconResultsPath, "live_subdomains.txt")
		urlsFile := filepath.Join(reconResultsPath, "urls.txt")
		if !utils.FileExistsAndIsNotEmpty(liveSubdomainsFile) && !utils.FileExistsAndIsNotEmpty(urlsFile) {
			detailedMsg := fmt.Sprintf("scan aborted for task '%s': Neither 'live_subdomains.txt' nor 'urls.txt' were found or are empty in the recon results directory. Please run the 'recon' command for this target first.", taskIdentifier)
			logger.Error(detailedMsg, "missing_files", []string{liveSubdomainsFile, urlsFile})
			return "", nil, fmt.Errorf(detailedMsg)
		}
		initialTargetsFile = liveSubdomainsFile
	}

	tempDir := filepath.Join(scanResultsPath, "tmp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create temporary directory for scan: %w", err)
	}

	portscanFile := filepath.Join(reconResultsPath, "portscan_results.txt")
	scanTargetsFile := filepath.Join(tempDir, "scan_targets.txt")
	
	filesToCombine := []string{initialTargetsFile, filepath.Join(reconResultsPath, "urls.txt"), portscanFile}
	if inputFile != "" {
		filesToCombine = []string{initialTargetsFile} // Se um arquivo de entrada for fornecido, apenas ele é usado.
	}
	if err := utils.CombineAndDeduplicateFiles(scanTargetsFile, filesToCombine...); err != nil {
		return "", nil, fmt.Errorf("failed to create unified target list for scan: %w", err)
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
		ctx:                ctx,
		target:             taskIdentifier,
		resultsPath:        scanResultsPath,
		logger:             logger,
		wafResultsFile:     filepath.Join(reconResultsPath, "waf_results.json"), 
		liveSubdomainsFile: filteredScanTargetsFile,
		urlsFile:           filteredScanTargetsFile,
		techFile:           filepath.Join(reconResultsPath, "httpx_tech.json"),
		vulnerabilityFile:  filepath.Join(scanResultsPath, "vulnerability_findings.txt"),
		nucleiScanFile:     filepath.Join(scanResultsPath, "nuclei_scan.txt"),
		cveScanFile:        filepath.Join(scanResultsPath, "cve_results.json"),
		niktoScanFile:      filepath.Join(scanResultsPath, "nikto_scan.txt"),
		dalfoxScanFile:     filepath.Join(scanResultsPath, "dalfox_xss.txt"),
		paramSpiderFile:    filepath.Join(scanResultsPath, "paramspider_urls.txt"),
		owaspScanFile:      filepath.Join(scanResultsPath, "owasp_scan.txt"),
		bbotScanFile:       filepath.Join(scanResultsPath, "bbot_scan.json"),
		apiFuzzFile:        filepath.Join(scanResultsPath, "apifuzz_results.json"),
		tempDir:            tempDir,
		wafMap:             make(map[string]string),
	}

	if err := loadWAFResults(state); err != nil {
		logger.Warn("Could not load WAF results, dynamic evasion will not be available.", "error", err)
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	workflow := map[string]scanStep{
		"paramspider": stepRunParamSpider,
		"vulntests":   stepRunVulnerabilityTests,
		"dalfox":      stepRunDalfox,
		"nuclei":      stepRunNucleiScan,
		"cvesearch":   stepRunCVESearch,
		"owasp":       stepRunOWASPTests,
		"nikto":       stepRunNikto,
		"bbot":      func(s *scanState) error { return stepRunBBot(s, isAggressive) },
		"apifuzz":   stepRunAPIFuzzing,
		"postscananalysis": stepRunPostScanAnalysis,
	}

	var executionOrder []string

	if len(onlySteps) > 0 {
		for _, step := range onlySteps {
			if _, ok := workflow[step]; !ok {
				return "", nil, fmt.Errorf("invalid step specified in --only flag: %s", step)
			}
		}
		executionOrder = onlySteps
		skipSet = make(map[string]struct{})
	} else {
		executionOrder = []string{"paramspider", "vulntests", "dalfox", "nuclei", "cvesearch", "owasp", "nikto", "bbot", "apifuzz"}
	}
	executionOrder = append(executionOrder, "postscananalysis")
	logger.Info("Starting vulnerability scan tasks.")

	if isInteractive {
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

			fmt.Printf("\n-> Press 's' and Enter to skip the current step: [%s]\n", stepName)
			state.logger.Info(fmt.Sprintf("[Step %d/%d] Starting: %s", i+1, totalSteps, stepName))

			go func() {
				stepState := *state
				stepState.ctx = stepCtx
				errChan <- stepFunc(&stepState)
			}()

			select {
			case err := <-errChan:
				if err != nil {
					state.logger.Error("A scan step failed", "step", stepName, "error", err)
				}
			case input := <-skipInputChan:
				if strings.ToLower(input) == "s" {
					state.logger.Warn("User requested to skip step. Cancelling...", "step", stepName)
					cancelStep()
					<-errChan // Aguarda a goroutine terminar após o cancelamento
				}
			case <-state.ctx.Done():
				slog.Info("Scan process cancelled.", "error", state.ctx.Err())
				cancelStep() // Cancela a etapa em andamento
				return "", nil, state.ctx.Err()
			}
			cancelStep()
		}
	} else {
		var wg sync.WaitGroup
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
				concurrencyLimit <- struct{}{}
				defer func() { <-concurrencyLimit }()

				if err := workflow[name](state); err != nil {
					logger.Error("A scan step failed", "step", name, "error", err)
					errChan <- fmt.Errorf("step %s failed: %w", name, err)
				}
			}(stepName)
		}
		wg.Wait()
		close(errChan)
	}
	logger.Info("Vulnerability scan process completed.")
	return generateScanSummary(state)
}

// WAFResult define a estrutura de uma entrada no arquivo de resultados do wafw00f.
type WAFResult struct {
	URL      string `json:"url"`
	Firewall string `json:"firewall"`
	Detected bool   `json:"detected"`
}

func loadWAFResults(s *scanState) error {
	if !config.Cfg.Engine.WAF.Enabled || !utils.FileExistsAndIsNotEmpty(s.wafResultsFile) {
		s.logger.Debug("WAF detection disabled or results file not found, skipping loading.", "file", s.wafResultsFile)
		return nil
	}

	file, err := os.Open(s.wafResultsFile)
	if err != nil {
		return fmt.Errorf("failed to open WAF results file: %w", err)
	}
	defer file.Close()

	var wafResults []WAFResult
	if err := json.NewDecoder(file).Decode(&wafResults); err != nil {
		s.logger.Warn("Failed to decode WAF results JSON, file might be invalid.", "file", s.wafResultsFile, "error", err)
		return nil
	}

	for _, result := range wafResults {
		if result.Detected && result.Firewall != "None" && result.Firewall != "" {
			parsedURL, err := url_pkg.Parse(result.URL)
			if err == nil {
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

func stepRunPostScanAnalysis(s *scanState) error {
	s.logger.Info("--- Starting: Post-Scan Analysis and Consolidation ---")

	nucleiFindings, err := analysis.ParseNucleiResults(s.nucleiScanFile, s.logger)
	if err != nil {
		s.logger.Warn("Failed to parse Nuclei results for summary", "error", err)
	}
	s.parsedNucleiFindings = append(s.parsedNucleiFindings, nucleiFindings...)

	httpxVulnFindings, err := analysis.ParseHttpxVulnerabilityResults(s.vulnerabilityFile, s.logger)
	if err != nil {
		s.logger.Warn("Failed to parse httpx vulnerability results for summary", "error", err)
	}
	s.parsedHttpxVulnFindings = httpxVulnFindings

	niktoFindings, err := analysis.ParseNiktoResults(s.niktoScanFile, s.logger)
	if err != nil {
		s.logger.Warn("Failed to parse Nikto results for summary", "error", err)
	}
	s.parsedNiktoFindings = append(s.parsedNiktoFindings, niktoFindings...)

	ffufResultsDir := filepath.Join(filepath.Dir(s.apiFuzzFile), "ffuf_results")
	ffufFindings, err := analysis.ParseFfufResults(ffufResultsDir, s.logger)
	if err != nil {
		s.logger.Warn("Failed to parse ffuf results for summary", "error", err)
	}
	s.parsedFfufFindings = append(s.parsedFfufFindings, ffufFindings...)

	dirsearchResultsDir := filepath.Join(filepath.Dir(s.apiFuzzFile), "dirsearch_results")
	dirsearchFindings, err := analysis.ParseDirsearchResults(dirsearchResultsDir, s.logger)
	if err != nil {
		s.logger.Warn("Failed to parse dirsearch results for summary", "error", err)
	}
	s.parsedDirsearchFindings = append(s.parsedDirsearchFindings, dirsearchFindings...)

	cveFindings, err := analysis.ParseCVEResults(s.cveScanFile, s.logger)
	if err != nil {
		s.logger.Warn("Failed to parse CVE results for summary", "error", err)
	}
	s.parsedCVEFindings = append(s.parsedCVEFindings, cveFindings...)

	owaspFindings, err := analysis.ParseNucleiResults(s.owaspScanFile, s.logger)
	if err == nil {
		s.parsedNucleiFindings = append(s.parsedNucleiFindings, owaspFindings...)
	}

	s.logger.Info("Post-scan analysis completed.")
	return nil
}

func stepRunVulnerabilityTests(s *scanState) error {
	s.logger.Info("--- Starting: Basic Vulnerability Tests (XSS, SQLi) ---")
	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Input file for vulnerability tests is empty after filtering, skipping.", "file", s.liveSubdomainsFile)
		return nil
	}

	err := tools.RunHttpxVulnerabilityScan(s.ctx, s.liveSubdomainsFile, s.vulnerabilityFile, s.tempDir, s.logger)
	if err != nil {
		s.logger.Warn("httpx (vulnerability) step finished with a non-zero exit code. This can happen if no URLs were reachable.", "error", err)
	}

	if utils.FileExistsAndIsNotEmpty(s.vulnerabilityFile) {
		s.logger.Info("Vulnerability testing completed", "output_file", s.vulnerabilityFile)
	}

	return nil
}

func stepRunNucleiScan(s *scanState) error {
	s.logger.Info("--- Starting: Vulnerability Scanning (Nuclei) ---")
	err := runNucleiScan(s, config.Cfg.Recon.Nuclei.Templates)
	if err != nil {
		s.logger.Warn("Nuclei scan encountered errors, but analysis will proceed with available data.", "error", err)
		return err
	}
	if utils.FileExistsAndIsNotEmpty(s.nucleiScanFile) {
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
	if utils.FileExistsAndIsNotEmpty(s.cveScanFile) {
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
	if utils.FileExistsAndIsNotEmpty(s.owaspScanFile) {
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
	if utils.FileExistsAndIsNotEmpty(s.niktoScanFile) {
		s.logger.Info("Nikto scan completed", "output_file", s.niktoScanFile)
	}
	return nil
}

func stepRunBBot(s *scanState, isAggressive bool) error {
	s.logger.Info("--- Starting: Full-scope Recon (BBot) ---")
	err := tools.RunBBot(s.ctx, []string{s.target}, s.bbotScanFile, s.tempDir, config.Cfg.Recon.BBot.Profile, isAggressive, s.logger)
	if err != nil {
		return err
	}
	if utils.FileExistsAndIsNotEmpty(s.bbotScanFile) {
		s.logger.Info("BBot scan completed", "output_file", s.bbotScanFile)
	}
	return nil
}

func stepRunAPIFuzzing(s *scanState) error {
	s.logger.Info("--- Starting: API Endpoint Fuzzing (ffuf) ---")

	jsURLs, err := recon.GetJSURLsFromFile(s.urlsFile)
	if err != nil {
		return fmt.Errorf("failed to get JS URLs for API fuzzing: %w", err)
	}
	if len(jsURLs) == 0 {
		s.logger.Info("No JavaScript URLs found in recon results, skipping API fuzzing.")
		return nil
	}

	endpointPatterns := []*regexp.Regexp{
		regexp.MustCompile(`['"](/[\w\-/._~:?#\[\]@!$&'()*+,;=]+){2,}['"]`), // Caminhos de URL genéricos com pelo menos 2 segmentos
		regexp.MustCompile(`['"](/api(/[\w\-/._~:?#\[\]@!$&'()*+,;=]+)*)['"]`), // Caminhos que começam com /api
		regexp.MustCompile(`['"](https?://[\w\-./?#&%=]+)['"]`),               // URLs completas
	}

	endpoints := make(map[string]struct{})
	var wg sync.WaitGroup
	var mu sync.Mutex
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

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
					endpointPath := strings.Trim(match[1], `"'`)
					if u, err := url_pkg.Parse(endpointPath); err == nil {
						path := strings.TrimPrefix(u.Path, "/")
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

	fuzzWordlist := config.Cfg.Wordlists.Fuzzing
	if !utils.FileExistsAndIsNotEmpty(fuzzWordlist) {
		s.logger.Warn("Fuzzing wordlist not configured or file not found, skipping API fuzzing.", "file", fuzzWordlist)
		return nil
	}

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
	endpointListFile.Close()

	s.logger.Info("Found endpoints to test", "count", len(endpoints))

	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Live subdomains file does not exist or is empty, skipping API fuzzing.", "file", s.liveSubdomainsFile)
		return nil
	}

	var ffufRateLimit int
	if config.Cfg.Engine.WAF.Enabled {
		profile := config.Cfg.Engine.WAF.DefaultProfile
		ffufRateLimit = profile.RateLimit
		s.logger.Info("Applying default WAF rate limit for API Fuzzing (ffuf).", "rate_limit", ffufRateLimit)
	}

	ffufOutputDir := filepath.Join(s.resultsPath, "ffuf_results")
	return tools.RunFfuf(s.ctx, s.liveSubdomainsFile, fuzzWordlist, ffufOutputDir, ffufRateLimit, s.logger)
}

func runNucleiScan(s *scanState, templates []string) error {
	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Input file for Nuclei does not exist or is empty, skipping.", "file", s.liveSubdomainsFile)
		return nil
	}
	if len(templates) == 0 {
		s.logger.Warn("No Nuclei templates specified, skipping scan.")
		return nil
	}

	groupedHosts := make(map[string][]string)
	allHosts, err := utils.ReadLines(s.liveSubdomainsFile)
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
			wafName = "none"
		}
		groupedHosts[wafName] = append(groupedHosts[wafName], host)
	}

	for wafName, hosts := range groupedHosts {
		if len(hosts) == 0 {
			continue
		}

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

		var useDefaultConcurrency bool
		var wafProfile config.WAFProfile

		if wafName == "none" {
			s.logger.Info("Running Nuclei for hosts with no WAF detected.", "host_count", len(hosts))
			useDefaultConcurrency = true
		} else {
			useDefaultConcurrency = false
			p, ok := config.Cfg.Engine.WAF.Profiles[wafName]
			if !ok {
				wafProfile = config.Cfg.Engine.WAF.DefaultProfile
				s.logger.Info("Running Nuclei with default WAF profile.", "waf", wafName, "host_count", len(hosts))
			} else {
				wafProfile = p
				s.logger.Info("Running Nuclei with specific WAF profile.", "waf", wafName, "host_count", len(hosts))
			}
		}

		err = tools.RunNuclei(s.ctx, tempInputFile.Name(), s.nucleiScanFile, s.tempDir, templates, wafProfile, useDefaultConcurrency, s.logger)
		if err != nil {
			s.logger.Warn("Nuclei scan for group finished with a non-zero exit code. This is often normal.", "group", wafName, "error", err)
		}
	}

	return nil
}

func stepRunDalfox(s *scanState) error {
	s.logger.Info("--- Starting: Advanced XSS Scanning (Dalfox) ---")
	err := tools.RunDalfox(s.ctx, s.liveSubdomainsFile, s.dalfoxScanFile, s.tempDir, s.logger)
	if err != nil {
		return err
	}
	if utils.FileExistsAndIsNotEmpty(s.dalfoxScanFile) {
		s.logger.Info("Dalfox XSS scan completed", "output_file", s.dalfoxScanFile)
	}
	return nil
}

func stepRunParamSpider(s *scanState) error {
	s.logger.Info("--- Starting: Parameter Discovery for IDOR/BAC (ParamSpider) ---")

	urls, err := utils.ReadLines(s.liveSubdomainsFile)
	if err != nil {
		return fmt.Errorf("failed to read filtered targets for ParamSpider: %w", err)
	}
	if len(urls) == 0 {
		s.logger.Warn("Filtered target list is empty, skipping ParamSpider.", "file", s.liveSubdomainsFile)
		return nil
	}

	uniqueDomains := make(map[string]struct{})
	for _, u := range urls {
		parsedURL, err := url_pkg.Parse(u)
		if err == nil && parsedURL.Hostname() != "" {
			uniqueDomains[parsedURL.Hostname()] = struct{}{}
		}
	}

	s.logger.Info("Extracted unique domains for ParamSpider", "count", len(uniqueDomains))

	var wg sync.WaitGroup
	var mu sync.Mutex
	allFoundParams := make(map[string]struct{})
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for domain := range uniqueDomains {
		wg.Add(1)
		concurrencyLimit <- struct{}{}
		go func(d string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			foundURLs, err := tools.RunParamSpider(s.ctx, d, s.logger)
			if err != nil {
				s.logger.Warn("ParamSpider failed for a domain, but continuing.", "domain", d, "error", err)
				return
			}

			if len(foundURLs) > 0 {
				mu.Lock()
				for _, foundURL := range foundURLs {
					allFoundParams[foundURL] = struct{}{}
				}
				mu.Unlock()
			}
		}(domain)
	}
	wg.Wait()

	err = utils.WriteLines(s.paramSpiderFile, allFoundParams)

	if utils.FileExistsAndIsNotEmpty(s.paramSpiderFile) {
		s.logger.Info("ParamSpider discovery completed", "output_file", s.paramSpiderFile)

		return utils.CombineAndDeduplicateFiles(s.liveSubdomainsFile, s.paramSpiderFile)
	}
	return nil

}

func runNikto(s *scanState) error {
	if !utils.FileExistsAndIsNotEmpty(s.liveSubdomainsFile) {
		s.logger.Warn("Input file for Nikto does not exist or is empty, skipping.", "file", s.liveSubdomainsFile)
		return nil
	}

	s.logger.Info("Executing external nikto command in parallel.")
	hosts, err := utils.ReadLines(s.liveSubdomainsFile)
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

				parsedURL, _ := url_pkg.Parse(h)
				wafName := ""
				if parsedURL != nil {
					wafName = s.wafMap[parsedURL.Hostname()]
				}

				stdout, err := tools.RunNikto(s.ctx, h, s.tempDir, wafName, s.logger)
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

func runCVESearch(ctx context.Context, techFile, outputFile string, logger *slog.Logger) error {
	return recon.RunCVESearch(ctx, techFile, outputFile, logger)
}

func generateScanSummary(state *scanState) (string, []string, error) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **Scan Summary for: %s**\n\n", state.target))

	nucleiCount := len(state.parsedNucleiFindings)
	if nucleiCount > 0 {
		summary.WriteString(fmt.Sprintf("• **Vulnerabilities (Nuclei):** %d findings detected.\n", nucleiCount))
		for _, f := range state.parsedNucleiFindings {
			if f.Info.Severity == "critical" || f.Info.Severity == "high" {
				summary.WriteString(fmt.Sprintf("  - [%s] %s @ %s\n", strings.ToUpper(f.Info.Severity), f.Info.Name, f.Host))
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

	totalFuzzFindings := len(state.parsedFfufFindings) + len(state.parsedDirsearchFindings)
	if totalFuzzFindings > 0 {
		summary.WriteString(fmt.Sprintf("• **Fuzzing:** %d interesting paths/responses found.\n", totalFuzzFindings))
	} else {
		summary.WriteString("• **Fuzzing:** No interesting paths or responses found.\n")
	}

	summary.WriteString(fmt.Sprintf("\n*Full scan results are saved in:* `%s`", state.resultsPath))

	resultFiles := []string{
		state.nucleiScanFile, state.cveScanFile, state.owaspScanFile,
		state.vulnerabilityFile, state.niktoScanFile, state.bbotScanFile,
		state.dalfoxScanFile, state.paramSpiderFile,
		state.apiFuzzFile,
	}

	return summary.String(), resultFiles, nil
}