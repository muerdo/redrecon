package cloud

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"redrecon/internal/config"
	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

type CloudState struct {
	ctx          context.Context
	target       string // Domain
	resultsPath  string
	logger       *slog.Logger
	proxyManager *utils.ProxyManager
}

// StartCloudRecon initiates the cloud reconnaissance workflow.
func StartCloudRecon(ctx context.Context, target string, proxyManager *utils.ProxyManager, logger *slog.Logger) error {
	logger.Info("Starting Cloud Recon", "target", target)

	state := &CloudState{
		ctx:          ctx,
		target:       target,
		logger:       logger,
		proxyManager: proxyManager,
		resultsPath:  filepath.Join("results", target, "cloud"),
	}

	if err := os.MkdirAll(state.resultsPath, 0755); err != nil {
		return fmt.Errorf("failed to create results dir: %w", err)
	}

	// 1. Check Azure Tenant
	if err := checkAzureTenant(state); err != nil {
		logger.Error("Azure tenant check failed", "error", err)
	}

	// 2. Cloud Enum (Buckets/Storage)
	if err := runCloudEnum(state); err != nil {
		logger.Error("CloudEnum failed", "error", err)
	}

	// 3. Analyze OpenID & Generate Custom Wordlist
	if err := analyzeOpenIDAndGenerateWordlist(state); err != nil {
		logger.Error("Failed to analyze OpenID/Generate Wordlist", "error", err)
	}

	// 4. Cloud Fuzzing (using generated wordlist)
	if err := runCloudFuzzing(state); err != nil {
		logger.Error("Cloud Fuzzing failed", "error", err)
	}

	// 5. Nuclei Cloud Templates
	// 5. Nuclei Cloud Templates
	if err := runNucleiCloud(state); err != nil {
		state.logger.Error("Nuclei Cloud failed", "error", err)
	}

	// 6. Recursive Subdomain Search (Subdomain of Subdomain)
	if err := runRecursiveSubdomainSearch(state); err != nil {
		state.logger.Error("Recursive Subdomain Search failed", "error", err)
	}

	// 7. Cloud Directory Fuzzing
	if err := runCloudDirectoryFuzzing(state); err != nil {
		state.logger.Error("Cloud Directory Fuzzing failed", "error", err)
	}

	// 8. Asset Dumper
	if err := runAssetDumper(state); err != nil {
		state.logger.Error("Asset Dumper failed", "error", err)
	}

	logger.Info("Cloud Recon Completed", "results", state.resultsPath)
	return nil
}

// checkAzureTenant checks if the domain is managed by Azure AD and extracts Tenant ID.
// Uses the GetUserRealm endpoint.
func checkAzureTenant(s *CloudState) error {
	s.logger.Info("--- Checking Azure AD Tenant ---")

	url := fmt.Sprintf("https://login.microsoftonline.com/getuserrealm.srf?login=user@%s&xml=1", s.target)

	client := &http.Client{Timeout: 10 * time.Second}
	if s.proxyManager != nil {
		// Basic proxy setup if available
		// In a real scenario, we'd use proxyManager.GetProxy()
	}

	req, _ := http.NewRequestWithContext(s.ctx, "GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Simple XML parsing
	type UserRealm struct {
		NameState        string `xml:"NameSpaceType"`
		DomainName       string `xml:"DomainName"`
		FederationGlobal string `xml:"FederationGlobalVersion"`
		AuthURL          string `xml:"AuthUrl"`
		STSAuthURL       string `xml:"STSAuthUrl"`
	}

	// Verify if it's Managed or Federated
	// Response usually contains <NameSpaceType>Managed</NameSpaceType> or Federated
	if strings.Contains(string(body), "<NameSpaceType>Managed") || strings.Contains(string(body), "<NameSpaceType>Federated") {
		s.logger.Info("Azure AD Tenant FOUND!", "domain", s.target)

		outputFile := filepath.Join(s.resultsPath, "azure_tenant.xml")
		_ = os.WriteFile(outputFile, body, 0644)
		s.logger.Info("Tenant info saved", "file", outputFile)

		// Extract OpenID info for Tenant ID
		getOpenIDConfig(s)
	} else {
		s.logger.Info("Domain does not appear to be an Azure AD tenant.")
	}

	return nil
}

func getOpenIDConfig(s *CloudState) {
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", s.target)
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		body, _ := io.ReadAll(resp.Body)
		outputFile := filepath.Join(s.resultsPath, "azure_openid_config.json")
		_ = os.WriteFile(outputFile, body, 0644)
		s.logger.Info("OpenID Config saved (contains Tenant ID)", "file", outputFile)
	}
}

func runCloudEnum(s *CloudState) error {
	s.logger.Info("--- Running Cloud Enumeration (Buckets/Storage) ---")
	outputFile := filepath.Join(s.resultsPath, "cloud_enum_results.json")
	// Using existing tool wrapper
	return tools.RunCloudenum(s.ctx, s.target, outputFile, s.logger)
}

func runNucleiCloud(s *CloudState) error {
	s.logger.Info("--- Running Nuclei Cloud Templates ---")

	// Create a temporary input file with the target domain
	inputFile := filepath.Join(s.resultsPath, "target.txt")
	_ = utils.WriteLines(inputFile, []string{s.target})

	_, err := tools.RunNuclei(
		s.ctx,
		inputFile,
		"cloud",         // Use 'cloud' tag
		"",              // Proxy
		nil, "", "", "", // Headers, cookies, auth
		s.logger,
		[]string{}, // Extra args
	)
	return err
}

// OpenIDConfig matches the JSON structure of Azure OpenID config
type OpenIDConfig struct {
	Issuer          string   `json:"issuer"`
	AuthEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint   string   `json:"token_endpoint"`
	ScopesSupported []string `json:"scopes_supported"`
	ClaimsSupported []string `json:"claims_supported"`
	CloudInstance   string   `json:"cloud_instance_name"`
	TenantRegion    string   `json:"tenant_region_scope"`
}

func analyzeOpenIDAndGenerateWordlist(s *CloudState) error {
	configFile := filepath.Join(s.resultsPath, "azure_openid_config.json")
	if !utils.FileExists(configFile) {
		s.logger.Info("No OpenID config file found, skipping analysis.")
		return nil
	}

	content, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}

	var config OpenIDConfig
	if err := json.Unmarshal(content, &config); err != nil {
		return fmt.Errorf("failed to parse openid config: %w", err)
	}

	s.logger.Info("Analyzing OpenID Config...", "issuer", config.Issuer)

	// Collect keywords
	keywords := []string{
		s.target,
		strings.Split(s.target, ".")[0],
		"azure", "blob", "storage", "container", "bucket", "aws", "s3",
		config.TenantRegion,
	}

	// Extract keywords from claims and scopes
	for _, scope := range config.ScopesSupported {
		// Scopes often look like "https://graph.microsoft.com/User.Read" or "openid"
		parts := strings.Split(scope, "/")
		lastPart := parts[len(parts)-1]
		keywords = append(keywords, strings.Split(lastPart, ".")...)
	}

	// Deduplicate
	uniqueMap := make(map[string]struct{})
	var finalKeywords []string
	for _, k := range keywords {
		k = strings.ToLower(strings.TrimSpace(k))
		if k != "" && len(k) > 2 {
			if _, exists := uniqueMap[k]; !exists {
				uniqueMap[k] = struct{}{}
				finalKeywords = append(finalKeywords, k)
			}
		}
	}

	// Basic permutations (e.g., target-backup, target-dev)
	suffixes := []string{"backup", "dev", "prod", "test", "stage", "staging", "logs", "internal", "secure"}
	var permutationList []string
	baseName := strings.Split(s.target, ".")[0]

	for _, suffix := range suffixes {
		permutationList = append(permutationList, fmt.Sprintf("%s-%s", baseName, suffix))
		permutationList = append(permutationList, fmt.Sprintf("%s%s", baseName, suffix))
		permutationList = append(permutationList, fmt.Sprintf("%s_%s", baseName, suffix))
	}

	finalList := append(finalKeywords, permutationList...)

	// Save wordlist
	wordlistPath := filepath.Join(s.resultsPath, "custom_cloud_wordlist.txt")
	if err := utils.WriteLines(wordlistPath, finalList); err != nil {
		return err
	}
	s.logger.Info("Custom cloud wordlist generated", "path", wordlistPath, "count", len(finalList))
	return nil
}

func runCloudFuzzing(s *CloudState) error {
	s.logger.Info("--- Running Cloud Fuzzing ---")
	wordlist := filepath.Join(s.resultsPath, "custom_cloud_wordlist.txt")
	if !utils.FileExists(wordlist) {
		return nil
	}

	// Fuzzing common permutations for Azure Blob and AWS S3
	// We will construct a list of potential URLs to check based on the wordlist

	var potentialURLs []string
	lines, _ := utils.ReadLines(wordlist)

	for _, w := range lines {
		// Azure Blob
		potentialURLs = append(potentialURLs, fmt.Sprintf("https://%s.blob.core.windows.net", w))
		potentialURLs = append(potentialURLs, fmt.Sprintf("https://%s.file.core.windows.net", w))
		// AWS S3 (Path style for fuzzing) - though virtual host is better
		potentialURLs = append(potentialURLs, fmt.Sprintf("https://%s.s3.amazonaws.com", w))
		// Generic
		potentialURLs = append(potentialURLs, fmt.Sprintf("https://%s", s.target)) // Just in case
	}

	// Use httpx for probing to see if they exist (status code check)
	probeInput := filepath.Join(s.resultsPath, "cloud_fuzz_candidates.txt")
	if err := utils.WriteLines(probeInput, potentialURLs); err != nil {
		return err
	}

	outputFile := filepath.Join(s.resultsPath, "cloud_assets_discovered.txt")

	// We assume RunHttpx exists in tools
	s.logger.Info("Probing potential cloud assets with Httpx...")

	// Create temp dir for responses
	tempDir := filepath.Join(s.resultsPath, "tmp")
	_ = os.MkdirAll(tempDir, 0755)

	return tools.RunHttpx(
		s.ctx,
		probeInput, // inputFile
		outputFile, // outputFile
		"",         // liveHostsOutputFile
		tempDir,
		true,            // followRedirects
		"80,443",        // ports
		false,           // techDetectOnly
		"",              // proxy
		nil, "", "", "", // headers, cookies, auth
		s.logger,
	)
}

// ----------------------
// New Cloud Exploration Functions
// ----------------------

func runRecursiveSubdomainSearch(s *CloudState) error {
	s.logger.Info("--- Running Recursive Subdomain Search on Cloud Domains ---")

	// 1. Identify Cloud Domains from previous steps (cloud_enum, cloud_fuzzing)
	// For simplicity, we'll scan the target domain itself for 'cloudy' subdomains if previous inputs aren't available,
	// but ideally we should parse 'cloud_assets_discovered.txt'.

	assetsFile := filepath.Join(s.resultsPath, "cloud_assets_discovered.txt")
	var domainsToScan []string

	if utils.FileExists(assetsFile) {
		lines, _ := utils.ReadLines(assetsFile)
		for _, line := range lines {
			// Extract domain from URL
			u, err := url.Parse(line)
			if err == nil {
				domainsToScan = append(domainsToScan, u.Hostname())
			}
		}
	}

	// Always fallback to scanning the main target if no cloud assets found yet,
	// OR add the main target to ensuring coverage.
	domainsToScan = append(domainsToScan, s.target)

	// Deduplicate
	domainsToScan = utils.UniqueStrings(domainsToScan)

	outputFile := filepath.Join(s.resultsPath, "recursive_subdomains.txt")

	// We'll use Subfinder on these domains
	// Note: tools.RunSubfinder needs to be flexible or we call it in a loop.
	// Assuming tools.RunSubfinder takes a single domain or we wrap it.

	s.logger.Info("Recursively scanning...", "count", len(domainsToScan))

	for _, domain := range domainsToScan {
		// Only scan if it looks like a cloud bucket/domain to save time?
		// Or just scan everything. Let's scan everything but shallowly.

		// Create a temp dir for this domain's results
		tempDir := filepath.Join(s.resultsPath, fmt.Sprintf("tmp_sub_%s", domain))
		_ = os.MkdirAll(tempDir, 0755)

		// RunSubfinder returns (outputFilePath, error)
		resultFile, err := tools.RunSubfinder(s.ctx, domain, tempDir, "", s.logger)
		if err != nil {
			s.logger.Warn("Subfinder failed for", "domain", domain, "error", err)
			continue
		}

		// Append to main output
		content, _ := os.ReadFile(resultFile)
		utils.AppendToFile(outputFile, string(content))
	}

	// Summarize
	lines, _ := utils.ReadLines(outputFile)
	unique := utils.UniqueStrings(lines)
	_ = utils.WriteLines(outputFile, unique) // Overwrite with unique

	s.logger.Info("Recursive Search Completed", "unique_subdomains", len(unique))
	if len(unique) > 0 {
		fmt.Printf("[+] Found %d unique subdomains via recursive search.\n", len(unique))
	}

	return nil
}

func runCloudDirectoryFuzzing(s *CloudState) error {
	s.logger.Info("--- Running Cloud Directory Fuzzing ---")

	// Targets: Cloud buckets/storage found in 'cloud_assets_discovered.txt' or 'cloud_enum_results.json'
	// For this implementation, we focus on 'cloud_assets_discovered.txt' (from fuzzing/probing).

	inputFile := filepath.Join(s.resultsPath, "cloud_assets_discovered.txt")
	if !utils.FileExists(inputFile) {
		s.logger.Info("No cloud assets to fuzz.")
		return nil
	}

	urls, _ := utils.ReadLines(inputFile)
	if len(urls) == 0 {
		return nil
	}

	// We use Feroxbuster for directory fuzzing
	outputFile := filepath.Join(s.resultsPath, "cloud_dir_fuzzing.txt")

	// We need a wordlist. Using a small default or config provided.
	wordlist := config.Cfg.Wordlists.Discovery // Default discovery wordlist
	if wordlist == "" {
		wordlist = "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt" // Fallback
	}

	// Run Feroxbuster
	// We need to pass the list of URLs. Feroxbuster supports stdin.
	// output will be in 'outputFile'

	// Create a temp dir for it
	tempDir := filepath.Join(s.resultsPath, "tmp_ferox")
	_ = os.MkdirAll(tempDir, 0755)

	err := tools.RunFeroxbuster(s.ctx, inputFile, outputFile, wordlist, tempDir, "", nil, "", s.logger)
	if err != nil {
		return err
	}

	// Process and Filter Output for Visual Feedback
	if utils.FileExists(outputFile) {
		lines, _ := utils.ReadLines(outputFile)
		s.logger.Info("Feroxbuster raw output lines", "count", len(lines))

		fmt.Println("--- interesting Cloud Paths Discovered ---")
		for _, line := range lines {
			// Feroxbuster Output format usually includes status code, etc.
			// We want to "enxugar" (trim) and show only interesting things.
			// Example raw: "200      GET        9l       32w      299c http://xyz.blob.core/secret"

			// We already filtered for 200, 301, 403 in the tool runner.
			// Let's look for 200/Listings.

			if strings.Contains(line, "200") || strings.Contains(line, "301") {
				// Printing the line directly can be messy, let's extract the URL if possible or just print cleaned line.
				// Simple heuristic: print lines with "200" in green (if we had color), else normal.
				fmt.Printf("found: %s\n", strings.TrimSpace(line))
			}
		}
		fmt.Println("------------------------------------------")
	}

	return nil
}

func runAssetDumper(s *CloudState) error {
	s.logger.Info("--- Running Cloud Asset Dumper ---")

	// Input: 'cloud_dir_fuzzing.txt' (results from feroxbuster)
	inputFile := filepath.Join(s.resultsPath, "cloud_dir_fuzzing.txt")
	if !utils.FileExists(inputFile) {
		s.logger.Info("No dir fuzzing results to dump from.")
		return nil
	}

	lines, _ := utils.ReadLines(inputFile)
	var urlsToDump []string

	// Extract URLs from Feroxbuster output
	// Output format: status ... url
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			lastField := fields[len(fields)-1]
			if strings.HasPrefix(lastField, "http") {
				urlsToDump = append(urlsToDump, lastField)
			}
		}
	}

	if len(urlsToDump) == 0 {
		return nil
	}

	dumpConf := DumpConfig{
		Extensions:  DefaultInterestingExtensions,
		MaxFileSize: 10 * 1024 * 1024, // 10MB
		OutputDir:   filepath.Join(s.resultsPath, "assets"),
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	fmt.Println("--- Dumping Interesting Assets ---")
	count := 0
	for _, u := range urlsToDump {
		path, err := DownloadAsset(u, dumpConf, client)
		if err == nil {
			fmt.Printf("[ASSET] Downloaded: %s -> %s\n", u, path)
			count++
		} else {
			// s.logger.Debug("Skipped", "url", u, "reason", err)
		}
	}
	fmt.Printf("--- Dumped %d assets ---\n", count)

	return nil
}
