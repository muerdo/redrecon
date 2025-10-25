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
	htmlFindingsFile     string
	vulnerabilityFile    string
	metadataFile         string
	resolversFile        string
	fuzzFile             string
	faviconFile          string
	nucleiScanFile       string
	cveScanFile          string
	niktoScanFile        string
	owaspScanFile        string
	bbotScanFile         string
	subdomainWordlist    string
	fuzzWordlist         string
}

type reconStep func(state *reconState) error

func StartRecon(target string, skipSteps []string) error {
	slog.Info("Starting reconnaissance process", "target", target)

	sanitizedTarget := sanitizeTargetForPath(target)
	resultsPath := filepath.Join("results", sanitizedTarget, "recon")
	slog.Info("Creating output directory", "path", resultsPath)

	err := os.MkdirAll(resultsPath, 0755)
	if err != nil {
		slog.Error("Failed to create directory", "path", resultsPath, "error", err)
		return fmt.Errorf("could not create directory %s: %w", resultsPath, err)
	}

	state := &reconState{
		ctx:                context.Background(),
		target:             target,
		resultsPath:        resultsPath,
		subdomainsFile:     filepath.Join(resultsPath, "subdomains.txt"),
		liveSubdomainsFile: filepath.Join(resultsPath, "live_subdomains.txt"),
		urlsFile:           filepath.Join(resultsPath, "urls.txt"),
		jsFindingsFile:     filepath.Join(resultsPath, "js_findings.txt"),
		htmlFindingsFile:   filepath.Join(resultsPath, "html_findings.txt"),
		vulnerabilityFile:  filepath.Join(resultsPath, "vulnerability_findings.txt"),
		metadataFile:       filepath.Join(resultsPath, "metadata.txt"),
		resolversFile:      filepath.Join(resultsPath, "resolvers.txt"),
		fuzzFile:           filepath.Join(resultsPath, "fuzzing_results.json"),
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

	executionOrder := []string{
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
			slog.Warn("Skipping step as requested", "step", stepName)
			continue
		}

		stepFunc := workflow[stepName]

		stepCtx, cancelStep := context.WithCancel(state.ctx)
		defer cancelStep()

		errChan := make(chan error, 1)

		fmt.Printf("\n-> Press 's' and Enter to skip the current step: [%s]\n", stepName)

		go func() {
			stepState := *state
			stepState.ctx = stepCtx
			errChan <- stepFunc(&stepState)
		}()

		select {
		case err := <-errChan:
			if err != nil {
				slog.Error("A reconnaissance step failed", "step", stepName, "error", err)
			}
		case input := <-skipInputChan:
			if strings.ToLower(input) == "s" {
				slog.Warn("User requested to skip step. Cancelling...", "step", stepName)
				cancelStep()
				<-errChan
			}
		case <-state.ctx.Done():
			slog.Info("Reconnaissance process cancelled.", "error", state.ctx.Err())
			cancelStep()
			return state.ctx.Err()
		}
	}

	slog.Info("Reconnaissance process completed.")
	return nil
}

func stepRunSubfinder(state *reconState) error {
	slog.Info("--- Starting: Passive Subdomain Enumeration (subfinder) ---")
	err := runSubfinder(state.ctx, state.target, state.subdomainsFile)
	if err == nil {
		slog.Info("Passive Subdomain Enumeration completed", "output_file", state.subdomainsFile)
	}
	return err
}

func stepRunDNSValidator(state *reconState) error {
	slog.Info("--- Starting: DNS Resolver Validation (dnsvalidator) ---")
	err := runDNSValidator(state.ctx, state.resolversFile)
	if err == nil {
		slog.Info("DNS Resolver Validation completed", "output_file", state.resolversFile)
	}
	return err
}

func stepRunShuffleDNS(state *reconState) error {
	slog.Info("--- Starting: Active Subdomain Enumeration (shuffledns) ---")
	foundSubdomains, err := runShuffleDNS(state.ctx, state.target, state.subdomainWordlist, state.resolversFile, state.subdomainsFile)
	if err != nil {
		return err
	}
	if len(foundSubdomains) > 0 {
		slog.Info("Active Subdomain Enumeration completed", "new_subdomains", len(foundSubdomains))
		return combineAndDeduplicateURLs(state.subdomainsFile, foundSubdomains)
	}
	slog.Info("Active Subdomain Enumeration completed with no new findings.")
	return nil
}

func stepRunHttpx(state *reconState) error {
	slog.Info("--- Starting: Live Subdomain Validation (httpx) ---")
	err := runHttpx(state.ctx, state.subdomainsFile, state.liveSubdomainsFile)
	if err == nil {
		slog.Info("Live Subdomain Validation completed", "output_file", state.liveSubdomainsFile)
	}
	return err
}

func stepRunHTMLAnalysis(state *reconState) error {
	slog.Info("--- Starting: HTML Source Code Analysis ---")
	err := runHTMLAnalysis(state.ctx, state.liveSubdomainsFile, state.htmlFindingsFile)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.htmlFindingsFile) {
		slog.Info("HTML analysis completed", "output_file", state.htmlFindingsFile)
	} else {
		slog.Info("HTML analysis completed with no new findings.")
	}
	return nil
}

func stepRunFaviconHash(state *reconState) error {
	slog.Info("--- Starting: Favicon Hash Analysis ---")
	err := runFaviconHash(state.ctx, state.liveSubdomainsFile, state.faviconFile)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.faviconFile) {
		slog.Info("Favicon hash analysis completed", "output_file", state.faviconFile)
	} else {
		slog.Info("Favicon hash analysis completed with no findings.")
	}
	return nil
}

func stepRunFuzzing(state *reconState) error {
	slog.Info("--- Starting: Directory and File Fuzzing (ffuf) ---")
	err := runFfuf(state.ctx, state.liveSubdomainsFile, state.fuzzWordlist, state.fuzzFile)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.fuzzFile) {
		slog.Info("Fuzzing completed", "output_file", state.fuzzFile)
	} else {
		slog.Info("Fuzzing completed with no findings.")
	}
	return nil
}

func stepRunKatana(state *reconState) error {
	slog.Info("--- Starting: URL Collection (katana) ---")
	err := runKatana(state.ctx, state.liveSubdomainsFile, state.urlsFile)
	if err == nil {
		slog.Info("URL Collection completed", "output_file", state.urlsFile)
	}
	return err
}

func stepRunJSAnalysis(state *reconState) error {
	slog.Info("--- Starting: JavaScript Analysis ---")
	err := runJSAnalysis(state.ctx, state.urlsFile, state.jsFindingsFile)
	if err == nil {
		slog.Info("JavaScript Analysis completed", "output_file", state.jsFindingsFile)
	}
	return err
}

func stepGetWaybackURLs(state *reconState) error {
	slog.Info("--- Starting: Augmenting with Wayback Machine URLs ---")
	waybackURLs, err := getWaybackURLs(state.ctx, state.target)
	if err != nil {
		slog.Warn("Failed to get URLs from Wayback Machine, continuing with existing URLs", "error", err)
		return nil
	}
	if len(waybackURLs) > 0 {
		err = combineAndDeduplicateURLs(state.urlsFile, waybackURLs)
		if err != nil {
			return fmt.Errorf("failed to combine Wayback URLs: %w", err)
		}
		slog.Info("Successfully added URLs from Wayback Machine", "count", len(waybackURLs))
	}
	return nil
}

func stepGetCSPDomains(state *reconState) error {
	slog.Info("--- Starting: CSP Header Subdomain Extraction ---")
	cspDomains, err := getCSPDomains(state.ctx, state.liveSubdomainsFile, state.target)
	if err != nil {
		slog.Warn("Failed to get subdomains from CSP headers", "error", err)
		return nil
	}
	if len(cspDomains) > 0 {
		slog.Info("Found new potential subdomains from CSP headers", "count", len(cspDomains))
		return combineAndDeduplicateURLs(state.subdomainsFile, cspDomains)
	}
	slog.Info("CSP Header Subdomain Extraction completed with no new findings.")
	return nil
}

func stepRunVulnerabilityTests(state *reconState) error {
	slog.Info("--- Starting: Basic Vulnerability Tests (XSS, SQLi) ---")
	err := runVulnerabilityTests(state.ctx, state.urlsFile, state.vulnerabilityFile)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.vulnerabilityFile) {
		slog.Info("Vulnerability testing completed", "output_file", state.vulnerabilityFile)
	} else {
		_ = os.Remove(state.vulnerabilityFile)
	}
	return nil
}

func stepRunNucleiScan(state *reconState) error {
	slog.Info("--- Starting: Vulnerability Scanning (Nuclei) ---")
	err := runNucleiScan(state.ctx, state.liveSubdomainsFile, state.nucleiScanFile)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.nucleiScanFile) {
		slog.Info("Nuclei scan completed", "output_file", state.nucleiScanFile)
	}
	return nil
}

func stepRunCVESearch(state *reconState) error {
	slog.Info("--- Starting: Known Vulnerability Search (CVE API) ---")
	techFile := filepath.Join(state.resultsPath, "httpx_vuln_scan.txt")
	err := runCVESearch(state.ctx, techFile, state.cveScanFile)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.cveScanFile) {
		slog.Info("CVE search completed", "output_file", state.cveScanFile)
	}
	return nil
}

func stepRunOWASPTests(state *reconState) error {
	slog.Info("--- Starting: OWASP Top 10 Intrusion Tests (Nuclei) ---")
	err := runOWASPTests(state.ctx, state.liveSubdomainsFile, state.owaspScanFile)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.owaspScanFile) {
		slog.Info("OWASP Top 10 tests completed", "output_file", state.owaspScanFile)
	} else {
		slog.Info("OWASP Top 10 tests completed with no findings.")
	}
	return nil
}

func stepRunNikto(state *reconState) error {
	slog.Info("--- Starting: Web Server Scanning (Nikto) ---")
	err := runNikto(state.ctx, state.liveSubdomainsFile, state.niktoScanFile)
	if err != nil {
		return err
	}
	if fileExistsAndIsNotEmpty(state.niktoScanFile) {
		slog.Info("Nikto scan completed", "output_file", state.niktoScanFile)
	}
	return nil
}

func stepRunBBot(state *reconState) error {
	slog.Info("--- Starting: Full-scope Recon (BBot) ---")
	err := runBBot(state.ctx, state.target, state.bbotScanFile)
	if err != nil {
		return err
	}
	return nil
}

func fileExistsAndIsNotEmpty(path string) bool {
	stat, err := os.Stat(path)
	return !os.IsNotExist(err) && stat.Size() > 0
}

func runSubfinder(ctx context.Context, target, outputFile string) error {
	slog.Info("Starting subfinder", "target", target)
	slog.Info("Executing external subfinder command. Ensure it's installed and configured in your system's PATH.")
	slog.Info("API keys should be configured in the default provider-config.yaml file.")

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
		slog.Error("Subfinder command failed", "error", err, "stderr", stderr.String())
		return fmt.Errorf("subfinder execution failed: %w\nStderr: %s", err, stderr.String())
	}

	return nil
}

func runHttpx(ctx context.Context, inputFile, outputFile string) error {
	slog.Info("Starting httpx to find live subdomains", "input", inputFile)

	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for httpx does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	slog.Info("Executing external httpx command. Ensure it's installed in your system's PATH.")

	cmd := exec.CommandContext(ctx, "httpx",
		"-l", inputFile,
		"-o", outputFile,
		"-threads", "50",
		"-silent",
		"-no-color",
		"-follow-redirects",
		"-random-agent",
		"-timeout", "10",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("httpx execution failed: %w\nStderr: %s", err, stderr.String())
	}

	return nil
}

func runKatana(ctx context.Context, inputFile, outputFile string) error {
	slog.Info("Starting Katana to crawl for URLs", "input", inputFile)

	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for Katana does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	slog.Info("Executing external katana command. Ensure it's installed in your system's PATH.")

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

func getWaybackURLs(ctx context.Context, domain string) ([]string, error) {
	slog.Info("Fetching URLs from Wayback Machine", "domain", domain)
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
		slog.Warn("Wayback Machine request failed, retrying...", "attempt", i+1, "error", err)
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
		slog.Info("Wayback Machine returned an empty response", "domain", domain)
		return nil, nil
	}

	var results [][]string
	if err := json.Unmarshal(body, &results); err != nil {
		slog.Warn("Could not unmarshal Wayback Machine JSON response", "error", err, "response", string(body))
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

	slog.Info("Found URLs in Wayback Machine", "count", len(urls), "domain", domain)
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

func parseSitemap(ctx context.Context, domain string) ([]string, error) {
	slog.Info("Attempting to parse sitemap", "domain", domain)
	var foundURLs []string
	var mu sync.Mutex
	var wg sync.WaitGroup

	var processSitemapURL func(sitemapURL string)
	processSitemapURL = func(sitemapURL string) {
		defer wg.Done()
		req, err := http.NewRequestWithContext(ctx, "GET", sitemapURL, nil)
		if err != nil {
			slog.Warn("Failed to create sitemap request", "url", sitemapURL, "error", err)
			return
		}

		client := &http.Client{Timeout: 20 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			slog.Warn("Failed to fetch sitemap", "url", sitemapURL, "error", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return
		}

		var reader io.Reader = resp.Body
		if strings.HasSuffix(sitemapURL, ".gz") {
			gzReader, err := gzip.NewReader(resp.Body)
			if err != nil {
				slog.Warn("Failed to create gzip reader for sitemap", "url", sitemapURL, "error", err)
				return
			}
			defer gzReader.Close()
			reader = gzReader
		}

		body, err := io.ReadAll(reader)
		if err != nil {
			slog.Warn("Failed to read sitemap body", "url", sitemapURL, "error", err)
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
	slog.Info("Sitemap parsing finished", "urls_found", len(foundURLs))
	return foundURLs, nil
}

func isMetadataTarget(urlStr string) bool {
	lowerURL := strings.ToLower(urlStr)
	extensions := []string{".pdf", ".jpg", ".jpeg", ".png", ".gif"}
	for _, ext := range extensions {
		if strings.HasSuffix(lowerURL, ext) {
			return true
		}
	}
	return false
}

func analyzeFileMetadata(wg *sync.WaitGroup, urlStr string, writer *bufio.Writer, mu *sync.Mutex) {
	defer wg.Done()
	slog.Debug("Analyzing file for metadata", "url", urlStr)

	resp, err := http.Get(urlStr)
	if err != nil {
		slog.Error("Failed to download file for metadata analysis", "url", urlStr, "error", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		slog.Warn("Failed to download file for metadata, non-200 status", "url", urlStr, "status", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		slog.Error("Failed to read file body for metadata analysis", "url", urlStr, "error", err)
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
		slog.Info("Found metadata in file", "url", urlStr)
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

func getJSURLsFromFile(inputFile string) ([]string, error) {
	file, err := os.Open(inputFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open input file %s: %w", inputFile, err)
	}
	defer file.Close()

	var jsURLs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasSuffix(line, ".js") {
			jsURLs = append(jsURLs, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input file %s: %w", inputFile, err)
	}
	return jsURLs, nil
}

func downloadContent(urlStr string) ([]byte, error) {
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

// beautifyJS executa a ferramenta externa 'jsbeautifier-go' para formatar o código JS.
func beautifyJS(jsContent string, urlStr string) string {
	cmd := exec.Command("jsbeautifier-go")
	cmd.Stdin = strings.NewReader(jsContent)
	var out bytes.Buffer
	cmd.Stdout = &out

	if err := cmd.Run(); err != nil {
		slog.Warn("Failed to run 'jsbeautifier-go'. Analyzing original content.", "url", urlStr, "error", err, "help", "Ensure 'jsbeautifier-go' is installed: go install github.com/ditashi/jsbeautifier-go@latest")
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

func processSingleJSURL(ctx context.Context, jsURL string, writer *bufio.Writer, mu *sync.Mutex) {
	slog.Debug("Processing JS file", "url", jsURL)

	body, err := downloadContent(jsURL)
	if err != nil {
		slog.Error("Failed to process JS file", "url", jsURL, "error", err)
		return
	}

	jsContent := string(body)
	beautifiedContent := beautifyJS(jsContent, jsURL)

	jsSecrets, jsEndpoints := analyzeContentForPatterns(beautifiedContent)

	if len(jsSecrets) > 0 || len(jsEndpoints) > 0 {
		slog.Info("Found patterns in JS file", "url", jsURL)
		findings := URLFindings{
			URL:       jsURL,
			Secrets:   jsSecrets,
			Endpoints: jsEndpoints,
		}
		writeFindings(writer, mu, "JS", findings)
	}

	findAndAnalyzeSourcemap(jsURL, beautifiedContent, writer, mu)
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

func runJSAnalysis(ctx context.Context, inputFile, outputFile string) error {
	slog.Info("Starting JavaScript analysis", "input", inputFile)
	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for JS analysis does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	jsURLs, err := getJSURLsFromFile(inputFile)
	if err != nil {
		return err
	}
	if len(jsURLs) == 0 {
		slog.Warn("No JavaScript URLs found in input file, skipping JS analysis.", "file", inputFile)
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
			slog.Info("JS analysis cancelled by context", "error", ctx.Err())
			return ctx.Err()
		case concurrencyLimit <- struct{}{}:
			wg.Add(1)
			go func(urlStr string) {
				defer wg.Done()
				defer func() { <-concurrencyLimit }()
				processSingleJSURL(ctx, urlStr, writer, &muWriter)
			}(jsURL)
		}
	}
	wg.Wait()
	return nil
}

func findAndAnalyzeSourcemap(jsURL, jsContent string, writer *bufio.Writer, mu *sync.Mutex) {
	matches := sourceMappingURLRegex.FindStringSubmatch(jsContent)
	if len(matches) < 2 {
		return
	}

	sourceMapURL := strings.TrimSpace(matches[1])
	slog.Debug("Found sourcemap reference", "js_url", jsURL, "sourcemap_url", sourceMapURL)

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
		slog.Debug("Downloading sourcemap", "url", absoluteSourceMapURL)
		sourceMapContent, err = downloadContent(absoluteSourceMapURL)
	}

	if err != nil {
		slog.Warn("Failed to retrieve or decode sourcemap", "js_url", jsURL, "error", err)
		return
	}

	smSecrets, smEndpoints := analyzeSourceMap(jsURL, sourceMapContent)

	if len(smSecrets) > 0 || len(smEndpoints) > 0 {
		slog.Info("Found patterns in sourcemap", "js_url", jsURL)
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

func analyzeSourceMap(jsURL string, content []byte) (allSecrets []Finding, allEndpoints []Finding) {
	var sm SourceMap
	if err := json.Unmarshal(content, &sm); err != nil {
		slog.Warn("Failed to unmarshal sourcemap", "js_url", jsURL, "error", err)
		return nil, nil
	}

	if len(sm.SourcesContent) == 0 {
		return nil, nil
	}

	slog.Info("Analyzing content from sourcemap", "js_url", jsURL, "source_files", len(sm.SourcesContent))
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

func runVulnerabilityTests(ctx context.Context, inputFile, outputFile string) error {
	slog.Info("Starting basic vulnerability tests (XSS, SQLi)", "input", inputFile)

	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for vulnerability tests is empty, skipping.", "file", inputFile)
		return nil
	}

	slog.Info("Executing external httpx command for vulnerability tests. Ensure it's installed in your system's PATH.")

	xssPayloads := `"><script>alert('XSS')</script>,'"--> </style></scRipt><scRipt>alert('XSS')</scRipt>`

	cmd := exec.CommandContext(ctx, "httpx",
		"-l", inputFile,
		"-o", filepath.Join(filepath.Dir(outputFile), "httpx_vuln_scan.txt"),
		"-silent",
		"-no-color",
		"-threads", fmt.Sprintf("%d", config.Cfg.Engine.MaxParallelTasks),
		"-timeout", "10",
		"-follow-redirects",
		"-random-agent",
		"-xss",
		"-xss-payload", xssPayloads,
		"-sqli",
		"-unsafe",
	)

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("httpx (vulnerability) execution failed: %w\nStderr: %s", err, stderr.String())
	}

	return nil
}

func runDNSValidator(ctx context.Context, outputFile string) error {
	slog.Info("Validating public DNS resolvers with dnsvalidator. This may take a moment...")
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
		return fmt.Errorf("dnsvalidator execution failed: %w\nStderr: %s", err, stderr.String())
	}

	if !fileExistsAndIsNotEmpty(outputFile) {
		return fmt.Errorf("dnsvalidator ran but did not produce a resolver list")
	}

	return nil
}

func runShuffleDNS(ctx context.Context, domain, wordlist, resolversFile, subdomainsFile string) ([]string, error) {
	if !fileExistsAndIsNotEmpty(resolversFile) {
		slog.Warn("Resolvers file for shuffledns does not exist or is empty, skipping.", "file", resolversFile)
		return nil, nil
	}
	if (wordlist == "" || !fileExistsAndIsNotEmpty(wordlist)) && !fileExistsAndIsNotEmpty(subdomainsFile) {
		slog.Warn("Both subdomain wordlist and input subdomains file are missing, skipping shuffledns.", "wordlist", wordlist, "subdomains_file", subdomainsFile)
		return nil, nil
	}

	slog.Info("Executing external shuffledns command.", "domain", domain)

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

func runNucleiScan(ctx context.Context, inputFile, outputFile string) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for Nuclei does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	slog.Info("Executing external nuclei command. Ensure it's installed and templates are updated.")

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
		slog.Info("Using custom Nuclei templates from config", "templates", config.Cfg.Recon.Nuclei.Templates)
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

func runOWASPTests(ctx context.Context, inputFile, outputFile string) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for OWASP tests does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	slog.Info("Executing external nuclei command for OWASP Top 10 tests. Ensure it's installed and templates are updated.")

	owaspTemplates := config.Cfg.Recon.Nuclei.OWASPTemplates
	if len(owaspTemplates) == 0 {
		slog.Warn("No specific OWASP Top 10 templates configured. Using a default set.", "config_path", "config.Cfg.Recon.Nuclei.OWASPTemplates")
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

	return executeNucleiCommand(ctx, inputFile, outputFile, owaspTemplates)
}

func executeNucleiCommand(ctx context.Context, inputFile, outputFile string, templates []string) error {
	if !fileExistsAndIsNotEmpty(inputFile) || len(templates) == 0 {
		return nil
	}

	slog.Debug("Running Nuclei command", "input", inputFile, "output", outputFile, "templates", templates)

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

func runNikto(ctx context.Context, inputFile, outputFile string) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for Nikto does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	slog.Info("Executing external nikto command in parallel. Ensure it's installed in your system's PATH.")

	hosts, err := readLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts from input file for Nikto: %w", err)
	}
	if len(hosts) == 0 {
		slog.Info("No hosts found in input file for Nikto, skipping scan.", "file", inputFile)
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
			slog.Info("Nikto scan cancelled by context", "error", ctx.Err())
			return ctx.Err()
		case concurrencyLimit <- struct{}{}:
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-concurrencyLimit }()

				slog.Debug("Running Nikto scan", "host", host)
				cmd := exec.CommandContext(ctx, "nikto", "-h", host, "-Format", "txt")

				var stdoutBuf, stderrBuf bytes.Buffer
				cmd.Stdout = &stdoutBuf
				cmd.Stderr = &stderrBuf

				err := cmd.Run()
				if err != nil {
					slog.Warn("Nikto scan for host failed", "host", host, "error", err, "stderr", stderrBuf.String())
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

func runBBot(ctx context.Context, target, outputFile string) error {
	slog.Info("Executing external bbot command. Ensure it's installed and configured.")

	profile := "recon-light"
	if config.Cfg.Recon.BBot.Profile != "" {
		profile = config.Cfg.Recon.BBot.Profile
	}
	slog.Info("Using bbot profile", "profile", profile)

	cmd := exec.CommandContext(ctx, "bbot", "-t", target, "-f", profile, "-o", outputFile, "-y")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bbot execution failed: %w", err)
	}
	slog.Info("BBot scan completed", "output_file", outputFile)
	return nil
}

type FaviconResult struct {
	Host         string `json:"host"`
	FaviconURL   string `json:"favicon_url"`
	Murmur3Hash  string `json:"murmur3_hash"`
	ShodanSearch string `json:"shodan_search"`
}

func runFaviconHash(ctx context.Context, inputFile, outputFile string) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for favicon analysis does not exist or is empty, skipping.", "file", inputFile)
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

			faviconURLs := findFaviconURLs(ctx, h)
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

func findFaviconURLs(ctx context.Context, hostURL string) []string {
	var foundURLs []string

	defaultFaviconURL, _ := url.Parse(hostURL)
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

func runCVESearch(ctx context.Context, techFile, outputFile string) error {
	if !fileExistsAndIsNotEmpty(techFile) {
		slog.Warn("Technology detection file does not exist or is empty, skipping CVE search.", "file", techFile)
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
		slog.Info("No technologies detected, skipping CVE search.")
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
			slog.Debug("Searching CVEs for technology", "tech", t)

			time.Sleep(1 * time.Second)

			apiURL := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&keywordExactMatch", url.QueryEscape(t))
			req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
			if err != nil {
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				slog.Warn("Failed to query NVD API", "tech", t, "error", err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				slog.Warn("NVD API returned non-200 status", "tech", t, "status", resp.StatusCode)
				return
			}

			var nvdResp NVDResponse
			if err := json.NewDecoder(resp.Body).Decode(&nvdResp); err != nil {
				slog.Warn("Failed to decode NVD API response", "tech", t, "error", err)
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

func runFfuf(ctx context.Context, inputFile, wordlist, outputFile string) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for ffuf does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}
	if wordlist == "" || !fileExistsAndIsNotEmpty(wordlist) {
		slog.Warn("Fuzzing wordlist not configured or file not found, skipping ffuf.", "file", wordlist)
		return nil
	}

	slog.Info("Executing external ffuf command. Ensure it's installed in your system's PATH.")

	hosts, err := readLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for ffuf: %w", err)
	}

	var allResults []interface{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, host := range hosts {
		wg.Add(1)
		concurrencyLimit <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-concurrencyLimit }()

			slog.Debug("Running ffuf scan", "host", h)
			cmd := exec.CommandContext(ctx, "ffuf", "-w", wordlist, "-u", h+"/FUZZ", "-o", "json", "-silent")
			output, err := cmd.Output()
			if err != nil {
				return
			}

			var result struct {
				Results []interface{} `json:"results"`
			}
			if json.Unmarshal(output, &result) == nil && len(result.Results) > 0 {
				mu.Lock()
				allResults = append(allResults, result.Results...)
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()

	if len(allResults) > 0 {
		finalOutput := map[string]interface{}{"results": allResults}
		fileData, err := json.MarshalIndent(finalOutput, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal ffuf results: %w", err)
		}
		return os.WriteFile(outputFile, fileData, 0644)
	}

	return nil
}

func getCSPDomains(ctx context.Context, liveSubdomainsFile, mainTarget string) ([]string, error) {
	if !fileExistsAndIsNotEmpty(liveSubdomainsFile) {
		slog.Warn("Live subdomains file for CSP analysis does not exist or is empty, skipping.", "file", liveSubdomainsFile)
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

func runHTMLAnalysis(ctx context.Context, inputFile, outputFile string) error {
	if !fileExistsAndIsNotEmpty(inputFile) {
		slog.Warn("Input file for HTML analysis does not exist or is empty, skipping.", "file", inputFile)
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

	c.OnResponse(func(r *colly.Response) {
		saveAndAnalyzeHTML(r, writer, &mu)
	})

	for _, host := range hosts {
		_ = c.Visit(host)
	}

	c.Wait()
	return nil
}

func saveAndAnalyzeHTML(r *colly.Response, secretsWriter *bufio.Writer, mu *sync.Mutex) {
	urlStr := r.Request.URL.String()
	sanitizedFilename := sanitizeTargetForPath(urlStr) + ".html"

	htmlFilesPath := filepath.Join("results", sanitizeTargetForPath(r.Request.URL.Hostname()), "recon", "html_files")
	if err := os.MkdirAll(htmlFilesPath, 0755); err != nil {
		slog.Error("Failed to create directory for HTML files", "path", htmlFilesPath, "error", err)
		return
	}

	filePath := filepath.Join(htmlFilesPath, sanitizedFilename)
	if err := os.WriteFile(filePath, r.Body, 0644); err != nil {
		slog.Error("Failed to save HTML file", "path", filePath, "error", err)
	} else {
		slog.Info("Saved HTML file", "path", filePath)
	}

	htmlContent := string(r.Body)
	for _, pattern := range secretPatterns {
		matches := pattern.FindAllString(htmlContent, -1)
		if len(matches) > 0 {
			mu.Lock()
			_, _ = secretsWriter.WriteString(fmt.Sprintf("[SECRET] HTML URL: %s, Pattern: %s, Matches: %v\n", urlStr, pattern.String(), matches))
			mu.Unlock()
			slog.Info("Found potential secret in HTML file", "url", urlStr, "pattern", pattern.String(), "matches", matches)
		}
	}
	for _, pattern := range endpointPatterns {
		matches := pattern.FindAllString(htmlContent, -1)
		if len(matches) > 0 {
			mu.Lock()
			_, _ = secretsWriter.WriteString(fmt.Sprintf("[ENDPOINT] HTML URL: %s, Pattern: %s, Matches: %v\n", urlStr, pattern.String(), matches))
			mu.Unlock()
			slog.Info("Found potential endpoint in HTML file", "url", urlStr, "pattern", pattern.String(), "matches", matches)
		}
	}
}
