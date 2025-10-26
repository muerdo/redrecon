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

func sanitizeTargetForPath(target string) string {
	replacer := strings.NewReplacer("http://", "", "https://", "", ":", "_", "/", "_", "?", "_", "&", "_", "=", "_")
	return replacer.Replace(target)
}

type reconState struct {
	ctx                  context.Context
	target               string
	resultsPath          string
	subdomainsFile       string
	liveSubdomainsFile   string
	urlsFile             string
	jsFindingsFile       string
	techFile             string
	htmlFindingsFile     string
	vulnerabilityFile    string
	metadataFile         string
	resolversFile        string
	fuzzResultsDir       string
	faviconFile          string
	nucleiScanFile       string
	cveScanFile          string
	niktoScanFile        string
	owaspScanFile        string
	bbotScanFile         string
	subdomainWordlist    string
	fuzzWordlist         string
	logger               *slog.Logger // Custom logger for this recon instance
}

type reconStep func(state *reconState) error

func StartRecon(target string, skipSteps []string, logger *slog.Logger) (string, error) {
	slog.Info("Starting reconnaissance process", "target", target)

	sanitizedTarget := sanitizeTargetForPath(target)
	resultsPath := filepath.Join("results", sanitizedTarget, "recon")
	slog.Info("Creating output directory", "path", resultsPath)

	err := os.MkdirAll(resultsPath, 0755)
	if err != nil && !os.IsExist(err) { // Check if error is not just directory already existing
		slog.Error("Failed to create directory", "path", resultsPath, "error", err)
		return "", fmt.Errorf("could not create directory %s: %w", resultsPath, err)
	}

	state := &reconState{
		ctx:                context.Background(),
		target:             target,
		resultsPath:        resultsPath,
		subdomainsFile:     filepath.Join(resultsPath, "subdomains.txt"),
		liveSubdomainsFile: filepath.Join(resultsPath, "live_subdomains.txt"),
		urlsFile:           filepath.Join(resultsPath, "urls.txt"),
		jsFindingsFile:     filepath.Join(resultsPath, "js_findings.txt"),
		logger:             logger, // Assign the custom logger
		techFile:           filepath.Join(resultsPath, "httpx_tech.json"),
		htmlFindingsFile:   filepath.Join(resultsPath, "html_findings.txt"),
		vulnerabilityFile:  filepath.Join(resultsPath, "vulnerability_findings.txt"),
		metadataFile:       filepath.Join(resultsPath, "metadata.txt"),
		resolversFile:      filepath.Join(resultsPath, "resolvers.txt"),
		fuzzResultsDir:     filepath.Join(resultsPath, "ffuf_results"),
		faviconFile:        filepath.Join(resultsPath, "favicon_hashes.json"),
		nucleiScanFile:     filepath.Join(resultsPath, "nuclei_scan.txt"),
		cveScanFile:        filepath.Join(resultsPath, "cve_results.json"),
		niktoScanFile:      filepath.Join(resultsPath, "nikto_scan.txt"),
		owaspScanFile:      filepath.Join(resultsPath, "owasp_scan.txt"),
		bbotScanFile:       filepath.Join(resultsPath, "bbot_scan.json"),
		subdomainWordlist:  config.Cfg.Wordlists.Subdomains,
		fuzzWordlist:       config.Cfg.Wordlists.Fuzzing,
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	workflow := map[string]reconStep{
		"subfinder":     stepRunSubfinder,
		"dnsvalidator":  stepRunDNSValidator,
		"shuffledns":    stepRunShuffleDNS,
		"httpx":         stepRunHttpx,
		"htmlanalysis":  stepRunHTMLAnalysis,
		"favicon":       stepRunFaviconHash,
		"ffuf":          stepRunFuzzing,
		"csp":           stepGetCSPDomains,
		"katana":        stepRunKatana,
		"wayback":       stepGetWaybackURLs,
		"jsanalysis":    stepRunJSAnalysis,
		"vulntests":     stepRunVulnerabilityTests,
		"nuclei":        stepRunNucleiScan,
		"cvesearch":     stepRunCVESearch,
		"owasp":         stepRunOWASPTests,
		"nikto":         stepRunNikto,
		"bbot":          stepRunBBot,
	}

	executionOrder := []string{ // Define the order of execution
		"subfinder", "dnsvalidator", "shuffledns", "httpx", "htmlanalysis", "favicon", "ffuf",
		"csp", "katana", "wayback", "jsanalysis", "vulntests", "nuclei", "cvesearch", "owasp", "nikto", "bbot",
	}

	slog.Info("Output directory created successfully. Starting reconnaissance tasks.")

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
			} // else if input is not 's', it's ignored and the step continues
		case <-state.ctx.Done():
			slog.Info("Reconnaissance process cancelled.", "error", state.ctx.Err())
			cancelStep()
			return "", state.ctx.Err()
		}
	}

	slog.Info("Reconnaissance process completed.")
	return generateReconSummary(state)
}

func stepRunSubfinder(state *reconState) error {
	state.logger.Info("--- Starting: Passive Subdomain Enumeration (subfinder) ---")
	err := runSubfinder(state.ctx, state.target, state.subdomainsFile, state.logger)
	if err == nil {
		state.logger.Info("Passive Subdomain Enumeration completed", "output_file", state.subdomainsFile)
	}
	return err
}

func stepRunDNSValidator(state *reconState) error {
	state.logger.Info("--- Starting: DNS Resolver Validation (dnsvalidator) ---")
	err := runDNSValidator(state.ctx, state.resolversFile, state.logger)
	if err == nil {
		state.logger.Info("DNS Resolver Validation completed", "output_file", state.resolversFile)
	}
	return err
}

func stepRunShuffleDNS(state *reconState) error {
	state.logger.Info("--- Starting: Active Subdomain Enumeration (shuffledns) ---")
	foundSubdomains, err := runShuffleDNS(state.ctx, state.target, state.subdomainWordlist, state.resolversFile, state.subdomainsFile, state.logger)
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
	state.logger.Info("--- Starting: Live Subdomain Validation (httpx) ---")
	err := runHttpx(state.ctx, state.subdomainsFile, state.liveSubdomainsFile, state.techFile, state.logger)
	if err == nil {
		state.logger.Info("Live Subdomain Validation completed", "output_file", state.liveSubdomainsFile)
	}
	return err
}

func stepRunHTMLAnalysis(state *reconState) error {
	state.logger.Info("--- Starting: HTML Source Code Analysis ---")
	err := runHTMLAnalysis(state.ctx, state.liveSubdomainsFile, state.htmlFindingsFile, state.logger)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.htmlFindingsFile) {
		state.logger.Info("HTML analysis completed", "output_file", state.htmlFindingsFile)
	} else {
		state.logger.Info("HTML analysis completed with no new findings.")
	}
	return nil
}

func stepRunFaviconHash(state *reconState) error {
	state.logger.Info("--- Starting: Favicon Hash Analysis ---")
	err := runFaviconHash(state.ctx, state.liveSubdomainsFile, state.faviconFile, state.logger)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.faviconFile) {
		state.logger.Info("Favicon hash analysis completed", "output_file", state.faviconFile)
	} else {
		state.logger.Info("Favicon hash analysis completed with no findings.")
	}
	return nil
}

func stepRunFuzzing(state *reconState) error {
	state.logger.Info("--- Starting: Directory and File Fuzzing (ffuf) ---")
	err := runFfuf(state.ctx, state.liveSubdomainsFile, state.fuzzWordlist, state.fuzzResultsDir, state.logger)
	if err != nil {
		return err
	}

	// Check if the directory was created and is not empty
	if dirExistsAndIsNotEmpty(state.fuzzResultsDir) {
		state.logger.Info("Fuzzing completed", "output_dir", state.fuzzResultsDir)
	} else {
		state.logger.Info("Fuzzing completed with no findings.")
	}
	return nil
}

func stepRunKatana(state *reconState) error {
	state.logger.Info("--- Starting: URL Collection (katana) ---")
	err := runKatana(state.ctx, state.liveSubdomainsFile, state.urlsFile, state.logger)
	if err == nil {
		state.logger.Info("URL Collection completed", "output_file", state.urlsFile)
	}
	return err
}

func stepRunJSAnalysis(state *reconState) error {
	state.logger.Info("--- Starting: JavaScript Analysis ---")
	err := runJSAnalysis(state.ctx, state.urlsFile, state.jsFindingsFile, state.logger)
	if err == nil {
		state.logger.Info("JavaScript Analysis completed", "output_file", state.jsFindingsFile)
	}
	return err
}

func stepGetWaybackURLs(state *reconState) error { // This function needs logger too
	state.logger.Info("--- Starting: Augmenting with Wayback Machine URLs ---")
	waybackURLs, err := getWaybackURLs(state.ctx, state.target, state.logger)
	if err != nil {
		state.logger.Warn("Failed to get URLs from Wayback Machine, continuing with existing URLs", "error", err)
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

func stepGetCSPDomains(state *reconState) error {
	state.logger.Info("--- Starting: CSP Header Subdomain Extraction ---")
	cspDomains, err := getCSPDomains(state.ctx, state.liveSubdomainsFile, state.target, state.logger)
	if err != nil { // This function needs logger too
		state.logger.Warn("Failed to get subdomains from CSP headers", "error", err)
		return nil
	}
	if len(cspDomains) > 0 {
		state.logger.Info("Found new potential subdomains from CSP headers", "count", len(cspDomains))
		return combineAndDeduplicateURLs(state.subdomainsFile, cspDomains)
	}
	state.logger.Info("CSP Header Subdomain Extraction completed with no new findings.")
	return nil
}

func stepRunVulnerabilityTests(state *reconState) error {
	state.logger.Info("--- Starting: Basic Vulnerability Tests (XSS, SQLi) ---")

	if !fileExistsAndIsNotEmpty(state.urlsFile) {
		state.logger.Warn("Input file for vulnerability tests is empty, skipping.", "file", state.urlsFile)
		return nil
	}

	state.logger.Info("Executing external httpx command for vulnerability tests.")
	xssPayloads := `"><script>alert('XSS')</script>,'"--> </style></scRipt><scRipt>alert('XSS')</scRipt>`

	cmd := exec.CommandContext(state.ctx, "httpx",
		"-l", state.urlsFile,
		"-o", state.vulnerabilityFile,
		"-silent",
		"-no-color",
		"-threads", fmt.Sprintf("%d", config.Cfg.Engine.MaxParallelTasks),
		"-timeout", "10",
		"-follow-redirects",
		"-random-agent",
		"-xss", "-xss-payload", xssPayloads,
		"-sqli",
		"-unsafe",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("httpx (vulnerability) execution failed: %w\nStderr: %s", err, stderr.String())
	} // This function needs logger too

	if fileExistsAndIsNotEmpty(state.vulnerabilityFile) {
		state.logger.Info("Vulnerability testing completed", "output_file", state.vulnerabilityFile)
	}
	return nil
}

func stepRunNucleiScan(state *reconState) error {
	state.logger.Info("--- Starting: Vulnerability Scanning (Nuclei) ---")
	err := runNucleiScan(state.ctx, state.liveSubdomainsFile, state.nucleiScanFile, state.logger)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.nucleiScanFile) { // This function needs logger too
		state.logger.Info("Nuclei scan completed", "output_file", state.nucleiScanFile)
	} // This function needs logger too
	return nil
}

func stepRunCVESearch(state *reconState) error {
	state.logger.Info("--- Starting: Known Vulnerability Search (CVE API) ---")
	err := runCVESearch(state.ctx, state.techFile, state.cveScanFile, state.logger)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.cveScanFile) { // This function needs logger too
		state.logger.Info("CVE search completed", "output_file", state.cveScanFile)
	} // This function needs logger too
	return nil
}

func stepRunOWASPTests(state *reconState) error { // This function needs logger too
	state.logger.Info("--- Starting: OWASP Top 10 Intrusion Tests (Nuclei) ---")
	err := runOWASPTests(state.ctx, state.liveSubdomainsFile, state.owaspScanFile, state.logger)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.owaspScanFile) {
		state.logger.Info("OWASP Top 10 tests completed", "output_file", state.owaspScanFile)
	} else { // This function needs logger too
		state.logger.Info("OWASP Top 10 tests completed with no findings.")
	}
	return nil
}

func stepRunNikto(state *reconState) error { // This function needs logger too
	state.logger.Info("--- Starting: Web Server Scanning (Nikto) ---")
	err := runNikto(state.ctx, state.liveSubdomainsFile, state.niktoScanFile, state.logger)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.niktoScanFile) {
		state.logger.Info("Nikto scan completed", "output_file", state.niktoScanFile)
	} // This function needs logger too
	return nil
}

func stepRunBBot(state *reconState) error {
	state.logger.Info("--- Starting: Full-scope Recon (BBot) ---")
	err := runBBot(state.ctx, state.target, state.bbotScanFile, state.logger)
	if err != nil {
		return err
	}
	return nil
}

func fileExistsAndIsNotEmpty(path string) bool {
	stat, err := os.Stat(path)
	return !os.IsNotExist(err) && stat.Size() > 0
}

func dirExistsAndIsNotEmpty(path string) bool {
	entries, err := os.ReadDir(path)
	// Return true if there's no error and there's at least one entry in the directory.
	return err == nil && len(entries) > 0
}

func runSubfinder(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	logger.Info("Starting subfinder", "target", target)
	logger.Info("Executing external subfinder command. Ensure it's installed and configured in your system's PATH.")
	logger.Info("API keys should be configured in the default provider-config.yaml file.")

	cmd := exec.CommandContext(ctx, "subfinder",
		"-d", target,
		"-o", outputFile,
		"-silent",
		"-t", "10",
		"-timeout", "30",
		"-max-time", "10",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		logger.Error("Subfinder command failed", "error", err, "stderr", stderr.String())
		return fmt.Errorf("subfinder execution failed: %w\nStderr: %s", err, stderr.String())
	}

	return nil
}

func runHttpx(ctx context.Context, inputFile, liveHostsOutputFile, techOutputFile string, logger *slog.Logger) error {
	logger.Info("Starting httpx to find live subdomains", "input", inputFile)

	if !fileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for httpx does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	logger.Info("Executing external httpx command. Ensure it's installed in your system's PATH.")

	cmd := exec.CommandContext(ctx, "httpx",
		"-l", inputFile,
		"-o", liveHostsOutputFile,
		"-threads", "50",
		"-silent",
		"-no-color",
		"-follow-redirects",
		"-random-agent",
		"-timeout", "10",
		// Probe for the top 1000 most common ports
		"-ports", "top-1000",
		// Add technology detection and JSON output for it
		"-tech-detect",
		"-json", "-o", techOutputFile,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("httpx execution failed: %w\nStderr: %s", err, stderr.String())
	}

	return nil
}

func runKatana(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	logger.Info("Starting Katana to crawl for URLs", "input", inputFile)

	if !fileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for Katana does not exist or is empty, skipping.", "file", inputFile)
		return nil
	} // This function needs logger too

	logger.Info("Executing external katana command. Ensure it's installed in your system's PATH.")

	cmd := exec.CommandContext(ctx, "katana",
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
		"-ef", "js,json,html,txt,xml",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("katana execution failed: %w\nStderr: %s", err, stderr.String())
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

func readLines(filePath string) ([]string, error) {
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
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

func isMetadataTarget(urlStr string) bool { // This function needs logger too
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
func analyzeFileMetadata(wg *sync.WaitGroup, urlStr string, writer *bufio.Writer, mu *sync.Mutex, logger *slog.Logger) {
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

func getJSURLsFromFile(inputFile string) ([]string, error) { // This function needs logger too
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

func downloadContent(urlStr string) ([]byte, error) { // This function needs logger too
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
func analyzeContentForPatterns(content string) (secrets []Finding, endpoints []Finding) {
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

	body, err := downloadContent(jsURL)
	if err != nil {
		logger.Error("Failed to process JS file", "url", jsURL, "error", err)
		return
	}

	jsContent := string(body)
	beautifiedContent := beautifyJS(jsContent, jsURL, logger)

	jsSecrets, jsEndpoints := analyzeContentForPatterns(beautifiedContent)

	if len(jsSecrets) > 0 || len(jsEndpoints) > 0 {
		logger.Info("Found patterns in JS file", "url", jsURL)
		findings := URLFindings{
			URL:       jsURL,
			Secrets:   jsSecrets,
			Endpoints: jsEndpoints,
		}
		writeFindings(writer, mu, "JS", findings)
	}

	findAndAnalyzeSourcemap(jsURL, beautifiedContent, writer, mu, logger)
}

func writeFindings(writer *bufio.Writer, mu *sync.Mutex, sourceType string, findings URLFindings) {
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
	if !fileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for JS analysis does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	jsURLs, err := getJSURLsFromFile(inputFile) // This function needs logger too
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
		sourceMapContent, err = downloadContent(absoluteSourceMapURL)
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
		writeFindings(writer, mu, "SOURCEMAP", findings)
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
		secrets, endpoints := analyzeContentForPatterns(sourceContent)
		if len(secrets) > 0 {
			allSecrets = append(allSecrets, secrets...)
		}
		if len(endpoints) > 0 {
			allEndpoints = append(allEndpoints, endpoints...)
		}
	}
	return allSecrets, allEndpoints
}

func runDNSValidator(ctx context.Context, outputFile string, logger *slog.Logger) error {
	logger.Info("Validating public DNS resolvers with dnsvalidator. This may take a moment...")
	resolversListURL := "https://public-dns.info/nameservers.txt"
	
	cmd := exec.CommandContext(ctx, "dnsvalidator",
		"-tL", resolversListURL,
		"-threads", "100",
		"-o", outputFile,
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("dnsvalidator execution failed: %w\nStderr: %s", err, stderr.String()) // This function needs logger too
	}

	if !fileExistsAndIsNotEmpty(outputFile) {
		return fmt.Errorf("dnsvalidator ran but did not produce a resolver list")
	} // This function needs logger too

	return nil
}

func runShuffleDNS(ctx context.Context, domain, wordlist, resolversFile, subdomainsFile string, logger *slog.Logger) ([]string, error) {
	if !fileExistsAndIsNotEmpty(resolversFile) {
		logger.Warn("Resolvers file for shuffledns does not exist or is empty, skipping.", "file", resolversFile)
		return nil, nil
	}
	if (wordlist == "" || !fileExistsAndIsNotEmpty(wordlist)) && !fileExistsAndIsNotEmpty(subdomainsFile) {
		logger.Warn("Both subdomain wordlist and input subdomains file are missing, skipping shuffledns.", "wordlist", wordlist, "subdomains_file", subdomainsFile)
		return nil, nil
	}

	logger.Info("Executing external shuffledns command.", "domain", domain)

	cmd := exec.CommandContext(ctx, "shuffledns",
		"-d", domain,
		"-w", wordlist,
		"-r", resolversFile,
		"-mode", "bruteforce",
		"-silent",
	)

	if fileExistsAndIsNotEmpty(subdomainsFile) {
		infile, err := os.Open(subdomainsFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open subdomains file for shuffledns stdin: %w", err)
		}
		defer infile.Close()
		cmd.Stdin = infile
	}

	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("shuffledns execution failed: %w\nStderr: %s", err, stderr.String())
	}

	var foundSubdomains []string
	for _, line := range strings.Split(out.String(), "\n") {
		if trimmedLine := strings.TrimSpace(line); trimmedLine != "" {
			foundSubdomains = append(foundSubdomains, trimmedLine)
		}
	}
	return foundSubdomains, nil
}

func runNucleiScan(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for Nuclei does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	
	logger.Info("Executing external nuclei command. Ensure it's installed and templates are updated.")

	args := []string{
		"-l", inputFile,
		"-o", outputFile,
		"-silent",
		"-no-color",
		"-retries", "2",
		"-timeout", "10",
		"-bulk-size", "50",
		"-concurrency", "25",
	}

	if len(config.Cfg.Recon.Nuclei.Templates) > 0 {
		logger.Info("Using custom Nuclei templates from config", "templates", config.Cfg.Recon.Nuclei.Templates)
		args = append(args, "-t", strings.Join(config.Cfg.Recon.Nuclei.Templates, ","))
	}

	cmd := exec.CommandContext(ctx, "nuclei", args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nuclei execution failed: %w\nStderr: %s", err, stderr.String())
	}

	return nil
}

func runOWASPTests(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for OWASP tests does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	
	logger.Info("Executing external nuclei command for OWASP Top 10 tests. Ensure it's installed and templates are updated.")

	owaspTemplates := config.Cfg.Recon.Nuclei.OWASPTemplates
	if len(owaspTemplates) == 0 {
		logger.Warn("No specific OWASP Top 10 templates configured. Using a default set.", "config_path", "config.Cfg.Recon.Nuclei.OWASPTemplates")
		owaspTemplates = []string{
			"http/vulnerabilities/access-control/",
			"http/vulnerabilities/command-injection/",
			"http/vulnerabilities/crlf-injection/",
			"http/vulnerabilities/file-inclusion/",
			"http/vulnerabilities/open-redirect/",
			"http/vulnerabilities/prototype-pollution/",
			"http/vulnerabilities/rce/",
			"http/vulnerabilities/ssrf/",
			"http/vulnerabilities/sql-injection/",
			"http/vulnerabilities/xss/",
			"http/miscellaneous/exposed-panels/",
			"http/miscellaneous/default-credentials/",
			"http/miscellaneous/insecure-configurations/",
			"http/technologies/outdated-versions/",
		}
	}

	return executeNucleiCommand(ctx, inputFile, outputFile, owaspTemplates, logger)
}

func executeNucleiCommand(ctx context.Context, inputFile, outputFile string, templates []string, logger *slog.Logger) error {
	if !fileExistsAndIsNotEmpty(inputFile) || len(templates) == 0 {
		return nil
	}

	logger.Debug("Running Nuclei command", "input", inputFile, "output", outputFile, "templates", templates)

	args := []string{
		"-l", inputFile,
		"-o", outputFile,
		"-silent",
		"-no-color",
		"-retries", "2",
		"-timeout", "10",
		"-bulk-size", "50",
		"-concurrency", "25",
		"-t", strings.Join(templates, ","),
	}

	cmd := exec.CommandContext(ctx, "nuclei", args...)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("nuclei execution failed: %w\nStderr: %s", err, stderr.String())
	}
	return nil
}

func runNikto(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for Nikto does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	logger.Info("Executing external nikto command in parallel. Ensure it's installed in your system's PATH.")

	hosts, err := readLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts from input file for Nikto: %w", err)
	}
	if len(hosts) == 0 {
		logger.Info("No hosts found in input file for Nikto, skipping scan.", "file", inputFile)
		return nil
	}

	outputFileHandle, err := os.OpenFile(outputFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed to open nikto output file: %w", err)
	}
	defer outputFileHandle.Close()

	var wg sync.WaitGroup
	var mu sync.Mutex
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, host := range hosts {
		host := host
		if host == "" {
			continue
		}

		select {
		case <-ctx.Done():
			logger.Info("Nikto scan cancelled by context", "error", ctx.Err())
			return ctx.Err()
		case concurrencyLimit <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-concurrencyLimit }()
				
				logger.Debug("Running Nikto scan", "host", host)

				parsedURL, err := url.Parse(host)
				if err != nil {
					logger.Warn("Failed to parse host URL for Nikto, skipping", "host", host, "error", err)
					return
				}

				args := []string{
					"-h", parsedURL.Hostname(),
					"-Format", "txt",
					"-Tuning", "1", // Focus on interesting findings
				}
				if parsedURL.Scheme == "https" {
					args = append(args, "-ssl")
				}
				if port := parsedURL.Port(); port != "" {
					args = append(args, "-p", port)
				}

				cmd := exec.CommandContext(ctx, "nikto", args...)

				var stdoutBuf, stderrBuf bytes.Buffer
				cmd.Stdout = &stdoutBuf
				cmd.Stderr = &stderrBuf

				err = cmd.Run()
				if err != nil {
					// Nikto often exits with code 1 for non-fatal errors (e.g., connection issues).
					// We log it but don't treat it as a hard failure to allow results to be saved.
					logger.Warn("Nikto scan for host completed with an error", "host", host, "error", err, "stderr", stderrBuf.String())
				}

				mu.Lock()
				defer mu.Unlock()
				if stdoutBuf.Len() > 0 {
					_, _ = outputFileHandle.WriteString(fmt.Sprintf("--- Nikto Scan for %s ---\n", host))
					_, _ = outputFileHandle.Write(stdoutBuf.Bytes())
					_, _ = outputFileHandle.WriteString("\n")
				}
				if stderrBuf.Len() > 0 {
					_, _ = outputFileHandle.WriteString(fmt.Sprintf("--- Nikto Errors for %s ---\n", host))
					_, _ = outputFileHandle.Write(stderrBuf.Bytes())
					_, _ = outputFileHandle.WriteString("\n")
				}
			}()
		}
	}

	wg.Wait()
	return nil
}

func runBBot(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	logger.Info("Executing external bbot command. Ensure it's installed and configured.")

	profile := "recon-light"
	if config.Cfg.Recon.BBot.Profile != "" {
		profile = config.Cfg.Recon.BBot.Profile
	}
	logger.Info("Using bbot profile", "profile", profile)

	cmd := exec.CommandContext(ctx, "bbot", "-t", target, "-f", profile, "-o", outputFile, "-y")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bbot execution failed: %w", err)
	}
	logger.Info("BBot scan completed", "output_file", outputFile)
	return nil
}

type FaviconResult struct {
	Host         string `json:"host"`
	FaviconURL   string `json:"favicon_url"`
	Murmur3Hash  string `json:"murmur3_hash"`
	ShodanSearch string `json:"shodan_search"`
}

func runFaviconHash(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for favicon analysis does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	
	hosts, err := readLines(inputFile)
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

			faviconURLs := findFaviconURLs(ctx, h, logger)
			if len(faviconURLs) == 0 {
				return
			}

			faviconURL := faviconURLs[0]

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

func findFaviconURLs(ctx context.Context, hostURL string, logger *slog.Logger) []string {
	var foundURLs []string

	defaultFaviconURL, _ := url.Parse(hostURL)
	defaultFaviconURL.Path = "/favicon.ico"
	foundURLs = append(foundURLs, defaultFaviconURL.String())

	c := colly.NewCollector(
		colly.MaxDepth(1),
		colly.Async(true),
	)
	c.SetClient(&http.Client{Timeout: 10 * time.Second})

	c.OnHTML("link[rel~='icon']", func(e *colly.HTMLElement) { // This function needs logger too
		href := e.Attr("href")
		absoluteURL := e.Request.AbsoluteURL(href)
		foundURLs = append(foundURLs, absoluteURL)
	})

	_ = c.Visit(hostURL)
	c.Wait()

	return foundURLs
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

func runCVESearch(ctx context.Context, techFile, outputFile string, logger *slog.Logger) error {
	if !fileExistsAndIsNotEmpty(techFile) {
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

func runFfuf(ctx context.Context, inputFile, wordlist, outputDir string, logger *slog.Logger) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for ffuf does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	if wordlist == "" || !fileExistsAndIsNotEmpty(wordlist) {
		logger.Warn("Fuzzing wordlist not configured or file not found, skipping ffuf.", "file", wordlist)
		return nil // This function needs logger too
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create ffuf output directory: %w", err)
	}

	logger.Info("Executing external ffuf command. Ensure it's installed in your system's PATH.")

	hosts, err := readLines(inputFile)
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

			sanitizedHost := sanitizeTargetForPath(h)
			hostOutputFile := filepath.Join(outputDir, fmt.Sprintf("%s.json", sanitizedHost))

			logger.Debug("Running ffuf scan", "host", h)
			cmd := exec.CommandContext(ctx, "ffuf",
				"-w", wordlist,
				"-u", h+"/FUZZ",
				"-o", hostOutputFile,
				"-of", "json",
				"-silent",
			)

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

func getCSPDomains(ctx context.Context, liveSubdomainsFile, mainTarget string, logger *slog.Logger) ([]string, error) {
	if !fileExistsAndIsNotEmpty(liveSubdomainsFile) {
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

func runHTMLAnalysis(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for HTML analysis does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	
	hosts, err := readLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for HTML analysis: %w", err)
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create HTML findings file: %w", err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	var mu sync.Mutex

	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(2),
	)

	_ = c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: config.Cfg.Engine.MaxParallelTasks,
	})

	c.OnResponse(func(r *colly.Response) { // This function needs logger too
		saveAndAnalyzeHTML(r, writer, &mu, logger)
	})

	for _, host := range hosts {
		_ = c.Visit(host)
	}

	c.Wait()
	return nil
}

func saveAndAnalyzeHTML(r *colly.Response, secretsWriter *bufio.Writer, mu *sync.Mutex, logger *slog.Logger) {
	urlStr := r.Request.URL.String()
	sanitizedFilename := sanitizeTargetForPath(urlStr) + ".html"

	htmlFilesPath := filepath.Join("results", sanitizeTargetForPath(r.Request.URL.Hostname()), "recon", "html_files")
	if err := os.MkdirAll(htmlFilesPath, 0755); err != nil {
		logger.Error("Failed to create directory for HTML files", "path", htmlFilesPath, "error", err)
		return
	}

	filePath := filepath.Join(htmlFilesPath, sanitizedFilename)
	if err := os.WriteFile(filePath, r.Body, 0644); err != nil {
		logger.Error("Failed to save HTML file", "path", filePath, "error", err)
	} else { // This function needs logger too
		logger.Info("Saved HTML file", "path", filePath)
	}

	htmlContent := string(r.Body)
	for _, pattern := range secretPatterns {
		matches := pattern.FindAllString(htmlContent, -1)
		if len(matches) > 0 {
			mu.Lock()
			_, _ = secretsWriter.WriteString(fmt.Sprintf("[SECRET] HTML URL: %s, Pattern: %s, Matches: %v\n", urlStr, pattern.String(), matches))
			mu.Unlock()
			logger.Info("Found potential secret in HTML file", "url", urlStr, "pattern", pattern.String(), "matches", matches)
		}
	}
	for _, pattern := range endpointPatterns {
		matches := pattern.FindAllString(htmlContent, -1)
		if len(matches) > 0 {
			mu.Lock()
			_, _ = secretsWriter.WriteString(fmt.Sprintf("[ENDPOINT] HTML URL: %s, Pattern: %s, Matches: %v\n", urlStr, pattern.String(), matches))
			mu.Unlock()
			logger.Info("Found potential endpoint in HTML file", "url", urlStr, "pattern", pattern.String(), "matches", matches)
		}
	}
}

func generateReconSummary(state *reconState) (string, error) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **Recon Summary for: %s**\n\n", state.target))

	// Helper to count lines in a file
	countLines := func(path string) int {
		if !fileExistsAndIsNotEmpty(path) {
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
	summary.WriteString(fmt.Sprintf("• **Nuclei Findings:** %d\n", countLines(state.nucleiScanFile)))
	summary.WriteString(fmt.Sprintf("• **OWASP Top 10 Findings:** %d\n", countLines(state.owaspScanFile)))
	summary.WriteString(fmt.Sprintf("• **Basic Vulnerabilities (XSS/SQLi):** %d\n", countLines(state.vulnerabilityFile)))

	summary.WriteString(fmt.Sprintf("\n*Full results are saved in:* `%s`", state.resultsPath))

	return summary.String(), nil
}
