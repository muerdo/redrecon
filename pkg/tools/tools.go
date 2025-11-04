package tools

import (
	"context"
	"fmt"
	"log/slog" // Adicionado: Importa o pacote bytes
	"os/exec"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"bytes"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
	"gopkg.in/yaml.v2"
)

func RunSubfinder(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	logger.Info("Executing external command: subfinder", "target", target)

	args := []string{
		"-d", target,
		"-all",
		"-t", "50",
		"-timeout", "30",
		"-tmp-dir", tempDir,
		"-max-time", "600",
		"-silent",
	}

	if !utils.CommandExists("subfinder") {
		return "", fmt.Errorf("subfinder not found in PATH")
	}

	configPath, err := createSubfinderConfig(tempDir)
	if err != nil {
		logger.Warn("Could not create subfinder API config, proceeding without API keys.", "error", err)
	} else if configPath != "" {
		defer os.Remove(configPath)
		args = append(args, "-pc", configPath)
	}

	output, err := utils.ExecuteCommand(ctx, logger, "subfinder", args...)
	if err != nil {
		keys := config.Cfg.APIKeys
		if keys.Chaos == "" && keys.SecurityTrails == "" && keys.Shodan == "" && keys.Github == "" && keys.Censys == "" {
			logger.Error("CRITICAL: Nenhuma chave de API encontrada em config.yaml. O Subfinder requer chaves de API para uma enumeração de subdomínios eficaz. Por favor, atualize sua configuração.")
		}
		return output, fmt.Errorf("subfinder execution failed: %w", err)
	}
	return output, nil
}

func RunAmass(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	logger.Info("Executing external command: amass", "target", target)
	if !utils.CommandExists("amass") {
		return "", fmt.Errorf("amass not found in PATH")
	}

	args := []string{
		"enum",
		"-passive",
		"-d", target,
		"-dir", tempDir, // Diretório para logs e outros arquivos do amass
		"-timeout", "15", // Timeout em minutos
	}

	return utils.ExecuteCommand(ctx, logger, "amass", args...)
}

func RunSublist3r(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	logger.Info("Executing external command: sublist3r", "target", target)
	if !utils.CommandExists("sublist3r") {
		return "", fmt.Errorf("sublist3r not found in PATH")
	}

	outputFile, err := os.CreateTemp(tempDir, "sublist3r_*.txt")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file for sublist3r: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFileName := outputFile.Name()
	outputFile.Close()

	args := []string{
		"-d", target,
		"-o", outputFileName,
		"-t", "10",
		"-v",
	}

	_, err = utils.ExecuteCommand(ctx, logger, "sublist3r", args...)
	if err != nil {
		logger.Warn("Sublist3r finished with an error, but attempting to read partial results.", "error", err)
	}

	content, readErr := os.ReadFile(outputFileName)
	if readErr != nil {
		return "", fmt.Errorf("failed to read sublist3r output file: %w", readErr)
	}

	return string(content), nil
}

func RunAssetfinder(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	logger.Info("Executing external command: assetfinder", "target", target)
	if !utils.CommandExists("assetfinder") {
		return "", fmt.Errorf("assetfinder not found in PATH. Install with: go install -v github.com/tomnomnom/assetfinder@latest")
	}

	args := []string{
		"--subs-only",
		target,
	}

	return utils.ExecuteCommand(ctx, logger, "assetfinder", args...)
}
func createSubfinderConfig(tempDir string) (string, error) {
	providerConfig := make(map[string][]string)
	keys := config.Cfg.APIKeys
	if keys.BinaryEdge != "" {
		providerConfig["binaryedge"] = []string{keys.BinaryEdge}
	}
	if keys.Censys != "" {
		providerConfig["censys"] = []string{keys.Censys}
	}
	if keys.Certspotter != "" {
		providerConfig["certspotter"] = []string{keys.Certspotter}
	}
	if keys.Chaos != "" {
		providerConfig["chaos"] = []string{keys.Chaos}
	}
	if keys.Github != "" {
		providerConfig["github"] = []string{keys.Github}
	}
	if keys.PassiveTotal != "" {
		providerConfig["passivetotal"] = []string{keys.PassiveTotal}
	}
	if keys.SecurityTrails != "" {
		providerConfig["securitytrails"] = []string{keys.SecurityTrails}
	}
	if keys.Shodan != "" {
		providerConfig["shodan"] = []string{keys.Shodan}
	}

	if len(providerConfig) == 0 {
		return "", nil
	}

	configFile, err := os.CreateTemp(tempDir, "subfinder-config-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary subfinder config file: %w", err)
	}
	defer configFile.Close()

	encoder := yaml.NewEncoder(configFile)
	err = encoder.Encode(providerConfig)
	if err != nil {
		return "", fmt.Errorf("failed to encode subfinder config to YAML: %w", err)
	}

	return configFile.Name(), nil
}

func RunHttpx(ctx context.Context, inputFile, outputFile, liveHostsOutputFile, tempDir string, followRedirects bool, ports string, techDetectOnly bool, logger *slog.Logger) error {
	logger.Info("Executing external command: httpx", "input", inputFile)
	if !utils.CommandExists("httpx") {
		return fmt.Errorf("httpx not found in PATH")
	}
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for httpx does not exist or is empty, skipping.", "file", inputFile, "tech_detect_mode", techDetectOnly)
		return nil
	}

	processedInputFile, err := utils.PreprocessForHttpxProbe(inputFile, tempDir, logger)
	if err != nil {
		return fmt.Errorf("failed to preprocess targets for httpx probe mode: %w", err)
	}
	defer os.Remove(processedInputFile)

	args := []string{
		"-l", processedInputFile,
		"-threads", "50",
		"-silent",
		"-timeout", "10",
		"-tmp-dir", tempDir,
	}

	if techDetectOnly {
		args = append(args, "-o", outputFile, "-json", "-status-code", "-title", "-tech-detect")
	} else {
		if followRedirects {
			args = append(args, "-follow-redirects")
		}
	}

	args = append(args, "-ports", "80,81,443,591,8000,8008,8080,8081,8443,8880,8888")
	args = append(args, "-probe")

	output, err := utils.ExecuteCommand(ctx, logger, "httpx", args...)

	if !techDetectOnly && err == nil && output != "" {
		if writeErr := os.WriteFile(liveHostsOutputFile, []byte(output), 0644); writeErr != nil {
			logger.Error("Failed to write live hosts output file from httpx stdout", "error", writeErr)
		}
	}
	return err
}

func RunHttpxVulnerabilityScan(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	logger.Info("Executing external command: httpx (vulnerability scan)", "input", inputFile)
	if !utils.CommandExists("httpx") {
		return fmt.Errorf("httpx not found in PATH")
	}
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for httpx vulnerability scan does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	processedInputFile, err := utils.PreprocessURLsForHttpx(inputFile, tempDir, logger)
	if err != nil {
		return fmt.Errorf("failed to preprocess URLs for httpx vulnerability scan: %w", err)
	}
	if processedInputFile != inputFile {
		defer os.Remove(processedInputFile)
	}

	if !utils.FileExistsAndIsNotEmpty(processedInputFile) {
		logger.Warn("No valid URLs found after preprocessing, skipping httpx vulnerability scan.", "original_file", inputFile)
		return nil
	}

	threads := config.Cfg.Engine.MaxParallelTasks
	if threads <= 0 {
		threads = 25
	}

	xssPayloads := `"><script>alert('XSS')</script>,'"--> </style></scRipt><scRipt>alert('XSS')</scRipt>`
	args := []string{
		"-l", processedInputFile,
		"-o", outputFile,
		"-silent", "-no-color",
		"-threads", fmt.Sprintf("%d", threads),
		"-tmp-dir", tempDir,
		"-timeout", "10",
		"-random-agent",
		"-xss", "-xss-payload", xssPayloads,
		"-sqli", "-unsafe", "-crlf", "-ssti",
	}

	_, err = utils.ExecuteCommand(ctx, logger, "httpx", args...)
	return err
}

func RunKatana(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	logger.Info("Executing external command: katana", "input", inputFile)
	if !utils.CommandExists("katana") {
		return fmt.Errorf("katana not found in PATH")
	}
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for katana does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	processedInputFile, err := utils.PreprocessURLsForHttpx(inputFile, tempDir, logger)
	if err != nil {
		return fmt.Errorf("failed to preprocess URLs for katana: %w", err)
	}
	if processedInputFile != inputFile {
		defer os.Remove(processedInputFile)
	}

	args := []string{
		"-list", processedInputFile,
		"-output", outputFile,
		"-silent",
		"-depth", "3",
		"-field-scope", "rdn",
		"-max-response-size", "2097152",
		"-timeout", "15",
		"-retry", "1",
		"-concurrency", "10",
		"-parallelism", "10",
		"-known-files", "all",
	}

	_, err = utils.ExecuteCommand(ctx, logger, "katana", args...)
	return err
}

func RunNuclei(ctx context.Context, inputFile, outputFile, tempDir string, templates []string, profile config.WAFProfile, useDefaultConcurrency bool, logger *slog.Logger) error {
	logger.Info("Executing external command: nuclei", "input", inputFile)
	if !utils.CommandExists("nuclei") {
		return fmt.Errorf("nuclei not found in PATH")
	}

	args := []string{
		"-l", inputFile,
		"-o", outputFile,
		"-silent", "-no-color",
		"-retries", "2", "-timeout", "10",
		"-tmp-dir", tempDir,
	}

	for _, t := range templates {
		args = append(args, "-t", t)
	}

	if useDefaultConcurrency {
		args = append(args, "-bulk-size", "50", "-c", "25", "-random-agent")
	} else {
		if profile.RateLimit > 0 {
			args = append(args, "-rate-limit", fmt.Sprintf("%d", profile.RateLimit))
		}
		if profile.Concurrency > 0 {
			args = append(args, "-c", fmt.Sprintf("%d", profile.Concurrency))
		}
		if proxyFile, ok := config.GetProxyFile(profile, tempDir); ok {
			args = append(args, "-proxy", proxyFile)
		}
	}

	_, err := utils.ExecuteCommand(ctx, logger, "nuclei", args...)
	return err
}

func RunNikto(ctx context.Context, host, tempDir string, wafName string, logger *slog.Logger) (string, error) {
	logger.Info("Executing external command: nikto", "host", host)
	if !utils.CommandExists("nikto") {
		return "", fmt.Errorf("nikto not found in PATH")
	}

	parsedURL, err := url.Parse(host)
	if err != nil {
		return "", fmt.Errorf("failed to parse host URL for Nikto: %w", err)
	}

	args := []string{"-h", parsedURL.Hostname(), "-Tuning", "1,2,3,4,5,b", "-maxtime", "10m"}

	if wafName != "" {
		profile, ok := config.Cfg.Engine.WAF.Profiles[wafName]
		if !ok {
			profile = config.Cfg.Engine.WAF.DefaultProfile
		}

		if profile.RateLimit > 0 {
			pauseSeconds := 1.0 / float64(profile.RateLimit)
			args = append(args, "-Pause", fmt.Sprintf("%.2f", pauseSeconds))
		}
		if proxyFile, ok := config.GetProxyFile(profile, tempDir); ok {
			logger.Warn("Nikto does not support proxy lists directly. Consider using proxychains.", "proxy_file", proxyFile)
		}
	}

	if parsedURL.Scheme == "https" {
		args = append(args, "-ssl")
	}
	if port := parsedURL.Port(); port != "" {
		args = append(args, "-p", port)
	}

	return utils.ExecuteCommand(ctx, logger, "nikto", args...)
}

func RunBBot(ctx context.Context, targets []string, outputFile, tempDir, preset string, isAggressive bool, logger *slog.Logger) error {
	logger.Info("Executing external command: bbot")
	if !utils.CommandExists("bbot") {
		return fmt.Errorf("bbot not found in PATH")
	}

	finalPreset := preset
	if isAggressive {
		finalPreset = "kitchen-sink"
	} else if finalPreset == "" {
		finalPreset = "recon-light"
	}
	logger.Info("Using bbot preset", "preset", finalPreset)

	args := []string{
		"-p", finalPreset,
		"-o", outputFile,
		"-om", "json",
		"-y",
	}
	for _, target := range targets {
		args = append(args, "-t", target)
	}

	_, err := utils.ExecuteCommand(ctx, logger, "bbot", args...)
	return err
}

func RunFfuf(ctx context.Context, inputFile, wordlist, outputDir string, rateLimit int, logger *slog.Logger) error {
	logger.Info("Executing external command: ffuf")
	if !utils.CommandExists("ffuf") {
		return fmt.Errorf("ffuf not found in PATH")
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create ffuf output directory: %w", err)
	}

	hosts, err := utils.ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for ffuf: %w", err)
	}

	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			concurrencyLimit <- struct{}{}
			defer func() { <-concurrencyLimit }()

			sanitizedHost := utils.SanitizeTargetForPath(h)
			hostOutputFile := filepath.Join(outputDir, fmt.Sprintf("%s.json", sanitizedHost))

			args := []string{
				"-w", wordlist,
				"-u", h + "/FUZZ",
				"-o", hostOutputFile,
				"-of", "json",
				"-ac",
				"-random-agent",
				"-noninteractive",
				"-maxtime", "300",
			}

			if rateLimit > 0 {
				args = append(args, "-rate", fmt.Sprintf("%d", rateLimit))
			}

			profile := config.Cfg.Engine.WAF.DefaultProfile
			if proxyFile, ok := config.GetProxyFile(profile, outputDir); ok {
				args = append(args, "-proxylist", proxyFile)
			}

			_, err := utils.ExecuteCommand(ctx, logger, "ffuf", args...)
			if err != nil {
				logger.Warn("ffuf scan for host failed", "host", h, "error", err)
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func RunDirsearch(ctx context.Context, inputFile, wordlist, outputDir string, rateLimit int, logger *slog.Logger) error {
	logger.Info("Executing external command: dirsearch")
	if !utils.CommandExists("dirsearch") {
		logger.Warn("dirsearch not found, skipping.", "help", "Install with: pip3 install dirsearch")
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
		go func(h string) {
			defer wg.Done()
			concurrencyLimit <- struct{}{}
			defer func() { <-concurrencyLimit }()

			sanitizedHost := utils.SanitizeTargetForPath(h)
			hostOutputFile := filepath.Join(outputDir, sanitizedHost)

			args := []string{
				"-u", h,
				"-w", wordlist,
				"--output=" + hostOutputFile,
				"--format=json",
				"--force-recursive",
				"--random-user-agents",
			}

			if rateLimit > 0 {
				args = append(args, fmt.Sprintf("--rate=%d", rateLimit))
			}

			_, err := utils.ExecuteCommand(ctx, logger, "dirsearch", args...)
			if err != nil {
				logger.Warn("dirsearch scan for host failed", "host", h, "error", err)
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func RunFeroxbuster(ctx context.Context, inputFile, wordlist, outputDir string, rateLimit int, logger *slog.Logger) error {
	logger.Info("Executing external command: feroxbuster")
	if !utils.CommandExists("feroxbuster") {
		logger.Warn("feroxbuster not found, skipping.", "help", "Install from: https://github.com/epi052/feroxbuster")
		return nil
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create feroxbuster output directory: %w", err)
	}

	hosts, err := utils.ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for feroxbuster: %w", err)
	}

	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			concurrencyLimit <- struct{}{}
			defer func() { <-concurrencyLimit }()

			sanitizedHost := utils.SanitizeTargetForPath(h)
			hostOutputFile := filepath.Join(outputDir, fmt.Sprintf("%s.json", sanitizedHost))

			args := []string{
				"--url", h,
				"--wordlist", wordlist,
				"--output", hostOutputFile,
				"--json",
				"--no-state",
				"--random-agent",
			}

			_, err := utils.ExecuteCommand(ctx, logger, "feroxbuster", args...)
			if err != nil {
				logger.Warn("feroxbuster scan for host failed", "host", h, "error", err)
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func RunGobuster(ctx context.Context, inputFile, wordlist, outputDir string, rateLimit int, logger *slog.Logger) error {
	logger.Info("Executing external command: gobuster")
	if !utils.CommandExists("gobuster") {
		logger.Warn("gobuster not found, skipping.", "help", "Install with: sudo apt install gobuster")
		return nil
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create gobuster output directory: %w", err)
	}

	hosts, err := utils.ReadLines(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read hosts for gobuster: %w", err)
	}

	var wg sync.WaitGroup
	concurrencyLimit := make(chan struct{}, config.Cfg.Engine.MaxParallelTasks)

	for _, host := range hosts {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			concurrencyLimit <- struct{}{}
			defer func() { <-concurrencyLimit }()

			sanitizedHost := utils.SanitizeTargetForPath(h)
			hostOutputFile := filepath.Join(outputDir, fmt.Sprintf("%s.txt", sanitizedHost))

			args := []string{
				"dir",
				"-u", h,
				"-w", wordlist,
				"-o", hostOutputFile,
				"-q",
				"--no-error",
				"-t", "50",
			}

			_, err := utils.ExecuteCommand(ctx, logger, "gobuster", args...)
			if err != nil {
				logger.Warn("gobuster scan for host failed", "host", h, "error", err)
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func RunDalfox(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	logger.Info("Executing external command: dalfox (XSS scan)", "input", inputFile)
	if !utils.CommandExists("dalfox") {
		logger.Warn("dalfox not found, skipping XSS scan.", "help", "go install -v github.com/hahwul/dalfox/v2@latest")
		return nil
	}
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for dalfox does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	args := []string{
		"file", inputFile,
		"-o", outputFile,
		"--silence",
		"--no-color",
		"--no-spinner",
		"--only-custom-payload",
	}

	_, err := utils.ExecuteCommand(ctx, logger, "dalfox", args...)
	if err != nil {
		logger.Warn("Dalfox scan finished with a non-zero exit code.", "error", err)
	}
	return nil
}

func RunParamSpider(ctx context.Context, domain string, logger *slog.Logger) ([]string, error) {
	logger.Info("Executing external command: paramspider", "domain", domain)
	if !utils.CommandExists("paramspider") {
		logger.Warn("paramspider not found, skipping parameter discovery.", "help", "pip3 install git+https://github.com/devanshbatham/ParamSpider")
		return nil, nil
	}

	args := []string{
		"-d", domain,
		"-s",
	}

	stdout, err := utils.ExecuteCommand(ctx, logger, "paramspider", args...)
	if err != nil {
		return nil, fmt.Errorf("paramspider execution failed for domain %s: %w", domain, err)
	}

	var validURLs []string
	for _, line := range strings.Split(stdout, "\n") {
		trimmedLine := strings.TrimSpace(line)
		if (strings.HasPrefix(trimmedLine, "http://") || strings.HasPrefix(trimmedLine, "https://")) && strings.Contains(trimmedLine, domain) {
			validURLs = append(validURLs, trimmedLine)
		}
	}

	return validURLs, nil
}

func RunEnum4linuxNG(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	logger.Info("Executing external command: enum4linux-ng", "target", target)
	if !utils.CommandExists("enum4linux-ng") {
		logger.Warn("enum4linux-ng not found, skipping SMB enumeration.", "help", "Install with: sudo apt install enum4linux-ng")
		return fmt.Errorf("enum4linux-ng not found in PATH")
	}

	args := []string{
		"-A",
		target,
	}

	output, err := utils.ExecuteCommand(ctx, logger, "enum4linux-ng", args...)
	if err != nil {
		return fmt.Errorf("enum4linux-ng execution failed: %w", err)
	}

	return os.WriteFile(outputFile, []byte(output), 0644)
}

func RunWafw00f(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	logger.Info("Executing external command: wafw00f", "input", inputFile)
	if !utils.CommandExists("wafw00f") {
		return fmt.Errorf("wafw00f not found in PATH")
	}

	args := []string{
		"-i", inputFile,
		"-o", outputFile,
		"-f", "json",
		"-a",
	}

	_, err := utils.ExecuteCommand(ctx, logger, "wafw00f", args...)
	if err != nil {
		logger.Warn("wafw00f execution finished with an error, but this might be acceptable.", "error", err)
	}
	return nil
}

func RunNaabu(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	logger.Info("Executing external command: naabu", "input", inputFile)
	if !utils.CommandExists("naabu") {
		logger.Warn("naabu not installed, skipping port scan.", "help", "go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")
		return nil
	}

	args := []string{
		"-list", inputFile,
		"-o", outputFile,
		"-silent",
		"-top-ports", "1000",
		"-rate", "1000",
	}

	_, err := utils.ExecuteCommand(ctx, logger, "naabu", args...)
	return err
}

func RunDnsxInfra(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	logger.Info("Executing external command: dnsx (infra mode)", "target", target)
	if !utils.CommandExists("dnsx") {
		return fmt.Errorf("dnsx not found in PATH")
	}

	args := []string{
		"-a", "-aaaa", "-cname", "-ns", "-txt", "-mx", "-soa",
		"-resp",
		"-silent",
	}

	cmd := exec.CommandContext(ctx, "dnsx", args...)
	cmd.Stdin = strings.NewReader(target)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("command 'dnsx' failed: %v. Stderr: %s", err, stderr.String())
	}

	return os.WriteFile(outputFile, stdout.Bytes(), 0644)
}

func RunCloudEnum(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	toolName := "cloudenum"
	if !utils.CommandExists(toolName) {
		logger.Warn("cloudenum not found, skipping cloud enumeration.", "help", "Install from: https://github.com/initstring/cloud_enum")
		return nil
	}

	logger.Info("Executing external command: cloudenum", "target", target)

	args := []string{
		"-k", target,
		"-j", outputFile,
		"-l", filepath.Join(filepath.Dir(outputFile), "cloudenum.log"),
	}

	_, err := utils.ExecuteCommand(ctx, logger, toolName, args...)
	if err != nil {
		logger.Warn("cloudenum finished with an error, but this may be expected.", "error", err)
	}

	return nil
}

func RunSslScan(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	toolName := "sslscan"
	if !utils.CommandExists(toolName) {
		logger.Warn("sslscan not found, skipping SSL/TLS scan.", "help", "Install with: sudo apt install sslscan")
		return nil
	}

	logger.Info("Executing external command: sslscan", "target", target)

	args := []string{
		"--show-certificate",
		"--no-colour",
		target,
	}

	output, err := utils.ExecuteCommand(ctx, logger, toolName, args...)
	if err != nil {
		return err
	}

	return os.WriteFile(outputFile, []byte(output), 0644)
}

func RunNmap(ctx context.Context, target, outputFile string, logger *slog.Logger, args ...string) error {
	logger.Info("Executing external command: nmap", "target", target)
	if !utils.CommandExists("nmap") {
		return fmt.Errorf("nmap not found in PATH")
	}

	fullArgs := append(args, target)
	_, err := utils.ExecuteCommand(ctx, logger, "nmap", fullArgs...)
	return err
}

func RunCrackMapExec(ctx context.Context, protocol, target string, logger *slog.Logger) (string, error) {
	toolName := "crackmapexec"
	if !utils.CommandExists(toolName) {
		toolName = "cme"
		if !utils.CommandExists(toolName) {
			logger.Warn("crackmapexec (or cme) not found, skipping.", "help", "Install with: sudo apt install crackmapexec")
			return "", nil
		}
	}

	args := []string{
		protocol,
		target,
	}

	return utils.ExecuteCommand(ctx, logger, toolName, args...)
}

func RunSipScan(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	toolName := "svmap"
	if !utils.CommandExists(toolName) {
		logger.Warn("svmap not found, skipping SIP/VoIP scan.", "help", "Install with: sudo apt install sipvicious")
		return nil
	}

	logger.Info("Executing external command: svmap", "target", target)

	output, err := utils.ExecuteCommand(ctx, logger, toolName, target)
	if err != nil {
		logger.Warn("svmap finished with an error, but this may be expected.", "error", err)
	}

	if output != "" {
		return os.WriteFile(outputFile, []byte(output), 0644)
	}

	return nil
}

func RunNmapRpcScan(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	logger.Info("Executing nmap RPC scan", "target", target)
	if !utils.CommandExists("nmap") {
		return fmt.Errorf("nmap not found in PATH")
	}

	args := []string{
		"-sV", "-p", "111,135",
		"--script=rpcinfo",
		"-oN", outputFile,
		target,
	}

	_, err := utils.ExecuteCommand(ctx, logger, "nmap", args...)
	return err
}