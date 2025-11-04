package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec" // Adicionado: Importa o pacote exec
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"bytes" // Adicionado: Importa o pacote bytes

	"redrecon/internal/config"
	"redrecon/pkg/utils"
	"gopkg.in/yaml.v2"
)

// RunSubfinder executa a ferramenta subfinder para enumeração de subdomínios.
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

	// Gera um arquivo de configuração temporário para o subfinder com as chaves de API.
	configPath, err := createSubfinderConfig(tempDir)
	if err != nil {
		logger.Warn("Could not create subfinder API config, proceeding without API keys.", "error", err)
	} else if configPath != "" {
		defer os.Remove(configPath)
		args = append(args, "-pc", configPath)
	}

	output, err := utils.ExecuteCommand(ctx, logger, "subfinder", args...)
	if err != nil {
		// A verificação de chaves de API é feita aqui, pois a falta delas é a causa mais comum de falha.
		// Se o subfinder falhar, informa ao usuário sobre a necessidade crítica das chaves.
		keys := config.Cfg.APIKeys
		if keys.Chaos == "" && keys.SecurityTrails == "" && keys.Shodan == "" && keys.Github == "" && keys.Censys == "" {
			logger.Error("CRITICAL: Nenhuma chave de API encontrada em config.yaml. O Subfinder requer chaves de API para uma enumeração de subdomínios eficaz. Por favor, atualize sua configuração.")
		}
		// Retorna a saída mesmo em caso de erro (pode conter resultados parciais) junto com o erro original.
		return output, fmt.Errorf("subfinder execution failed: %w", err)
	}
	return output, nil
}

// RunAmass executa a ferramenta amass para enumeração passiva de subdomínios.
func RunAmass(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	logger.Info("Executing external command: amass", "target", target)
	if !utils.CommandExists("amass") {
		return "", fmt.Errorf("amass not found in PATH")
	}

	// O amass pode ser lento, então definimos um timeout razoável.
	// Usamos o modo passivo para evitar qualquer tráfego direto para o alvo.
	args := []string{
		"enum",
		"-passive",
		"-d", target,
		"-dir", tempDir, // Diretório para logs e outros arquivos do amass
		"-timeout", "15", // Timeout em minutos
	}

	return utils.ExecuteCommand(ctx, logger, "amass", args...)
}

// RunSublist3r executa a ferramenta sublist3r.
func RunSublist3r(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	logger.Info("Executing external command: sublist3r", "target", target)
	if !utils.CommandExists("sublist3r") {
		return "", fmt.Errorf("sublist3r not found in PATH")
	}

	// Cria um arquivo de saída temporário para o sublist3r.
	// Isso evita que o banner da ferramenta polua o stdout.
	outputFile, err := os.CreateTemp(tempDir, "sublist3r_*.txt")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file for sublist3r: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFileName := outputFile.Name()
	outputFile.Close() // Fecha o handle para que o sublist3r possa escrever nele.

	args := []string{
		"-d", target,
		"-o", outputFileName, // Salva a saída no arquivo temporário.
		"-t", "10", // Define um número de threads.
		"-v", // Modo verboso para depuração, mas a saída vai para o arquivo.
	}

	// Executa o comando, mas ignora o stdout, pois a saída está no arquivo.
	_, err = utils.ExecuteCommand(ctx, logger, "sublist3r", args...)
	if err != nil {
		// Mesmo com erro, tenta ler o arquivo, pois pode haver resultados parciais.
		logger.Warn("Sublist3r finished with an error, but attempting to read partial results.", "error", err)
	}

	// Lê os resultados do arquivo de saída e retorna como uma string.
	content, readErr := os.ReadFile(outputFileName)
	if readErr != nil {
		return "", fmt.Errorf("failed to read sublist3r output file: %w", readErr)
	}

	return string(content), nil
}

// RunAssetfinder executa a ferramenta assetfinder.
func RunAssetfinder(ctx context.Context, target, tempDir string, logger *slog.Logger) (string, error) {
	logger.Info("Executing external command: assetfinder", "target", target)
	if !utils.CommandExists("assetfinder") {
		return "", fmt.Errorf("assetfinder not found in PATH. Install with: go install -v github.com/tomnomnom/assetfinder@latest")
	}

	// Assetfinder imprime para stdout, então capturamos a saída e a escrevemos no arquivo.
	args := []string{
		"--subs-only", // Garante que apenas subdomínios sejam retornados
		target,
	}

	return utils.ExecuteCommand(ctx, logger, "assetfinder", args...)
}
// createSubfinderConfig gera um arquivo provider-config.yaml temporário.
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

	// Subfinder espera um arquivo YAML, não JSON.
	encoder := yaml.NewEncoder(configFile)
	err = encoder.Encode(providerConfig)
	if err != nil {
		return "", fmt.Errorf("failed to encode subfinder config to YAML: %w", err)
	}

	return configFile.Name(), nil
}

// RunHttpx executa a ferramenta httpx para validação de hosts e descoberta de tecnologias.
func RunHttpx(ctx context.Context, inputFile, outputFile, liveHostsOutputFile, tempDir string, followRedirects bool, ports string, techDetectOnly bool, logger *slog.Logger) error {
	logger.Info("Executing external command: httpx", "input", inputFile)
	if !utils.CommandExists("httpx") {
		return fmt.Errorf("httpx not found in PATH")
	}
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for httpx does not exist or is empty, skipping.", "file", inputFile, "tech_detect_mode", techDetectOnly)
		return nil
	}

	// Pré-processa a lista de entrada para garantir que contenha apenas hostnames,
	// o que é o formato ideal para usar com as flags -probe e -ports.
	processedInputFile, err := utils.PreprocessForHttpxProbe(inputFile, tempDir, logger)
	if err != nil {
		return fmt.Errorf("failed to preprocess targets for httpx probe mode: %w", err)
	}
	defer os.Remove(processedInputFile)

	args := []string{
		"-l", processedInputFile, // Usa o arquivo pré-processado
		"-threads", "50",
		"-silent", // Usa -silent para que o stdout contenha apenas as URLs vivas.
		"-timeout", "10",
		"-tmp-dir", tempDir,
	}

	if techDetectOnly {
		// Modo de detecção de tecnologia: salva a saída JSON no arquivo de saída.
		args = append(args, "-o", outputFile, "-json", "-status-code", "-title", "-tech-detect")
	} else {
		// Modo de descoberta de hosts vivos: a saída vai para stdout.
		// A flag -random-agent foi removida, pois é o comportamento padrão agora.
		if followRedirects {
			args = append(args, "-follow-redirects")
		}
	}

	// CORREÇÃO: Adiciona um conjunto explícito de portas web comuns E a flag -probe.
	// Isso garante que, mesmo que o portscan não encontre nada, o httpx ainda tentará as portas mais óbvias.
	args = append(args, "-ports", "80,81,443,591,8000,8008,8080,8081,8443,8880,8888")
	args = append(args, "-probe") // Mantém o probe para verificar as portas padrão (80, 443) de forma eficiente.

	// Executa o comando e captura o stdout, que conterá a lista de hosts vivos.
	output, err := utils.ExecuteCommand(ctx, logger, "httpx", args...)

	// Se não estivermos no modo de detecção de tecnologia, a saída (stdout) são os hosts vivos.
	if !techDetectOnly && err == nil && output != "" {
		if writeErr := os.WriteFile(liveHostsOutputFile, []byte(output), 0644); writeErr != nil {
			logger.Error("Failed to write live hosts output file from httpx stdout", "error", writeErr)
		}
	}
	return err
}

// RunHttpxVulnerabilityScan executa o httpx para testes básicos de injeção.
func RunHttpxVulnerabilityScan(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	logger.Info("Executing external command: httpx (vulnerability scan)", "input", inputFile)
	if !utils.CommandExists("httpx") {
		return fmt.Errorf("httpx not found in PATH")
	}
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for httpx vulnerability scan does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	// Pré-processa o arquivo de entrada para garantir que todas as linhas sejam URLs válidas.
	// Isso evita que o httpx falhe com "exit status 2" se encontrar entradas como "host:port".
	processedInputFile, err := utils.PreprocessURLsForHttpx(inputFile, tempDir, logger)
	if err != nil {
		return fmt.Errorf("failed to preprocess URLs for httpx vulnerability scan: %w", err)
	}
	// Se o arquivo processado for diferente do original, removemos no final.
	if processedInputFile != inputFile {
		defer os.Remove(processedInputFile)
	}

	// Se após o processamento não houver URLs válidas, pulamos a etapa.
	if !utils.FileExistsAndIsNotEmpty(processedInputFile) {
		logger.Warn("No valid URLs found after preprocessing, skipping httpx vulnerability scan.", "original_file", inputFile)
		return nil
	}

	// Garante que o número de threads seja um valor razoável.
	threads := config.Cfg.Engine.MaxParallelTasks
	if threads <= 0 {
		threads = 25 // Define um padrão de 25 se a configuração for 0 ou negativa.
	}

	xssPayloads := `"><script>alert('XSS')</script>,'"--> </style></scRipt><scRipt>alert('XSS')</scRipt>`
	args := []string{
		"-l", processedInputFile, // Usa o arquivo pré-processado
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
	// O erro é tratado pelo chamador.
	return err
}

// RunKatana executa a ferramenta katana para crawling de URLs.
func RunKatana(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	logger.Info("Executing external command: katana", "input", inputFile)
	if !utils.CommandExists("katana") {
		return fmt.Errorf("katana not found in PATH")
	}
	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for katana does not exist or is empty, skipping.", "file", inputFile)
		return nil
	}

	// Adiciona uma etapa de pré-processamento para garantir que todas as entradas para o Katana sejam URLs válidas.
	// Isso evita o erro "exit status 2" se o arquivo de entrada contiver apenas domínios sem esquema.
	// Esta lógica está aqui para garantir que seja sempre aplicada, mesmo quando chamada de diferentes fluxos.
	processedInputFile, err := utils.PreprocessURLsForHttpx(inputFile, tempDir, logger)
	if err != nil {
		return fmt.Errorf("failed to preprocess URLs for katana: %w", err)
	}
	if processedInputFile != inputFile {
		defer os.Remove(processedInputFile)
	}

	args := []string{
		"-list", processedInputFile, // Usa o arquivo pré-processado
		"-output", outputFile,
		"-silent",
		"-depth", "3",
		"-field-scope", "rdn", // Mantém o escopo para subdomínios e domínios raiz
		"-max-response-size", "2097152", // Flag atualizada para limitar o tamanho do corpo da resposta
		"-timeout", "15",
		"-retry", "1",
		"-concurrency", "10",
		"-parallelism", "10",
		"-known-files", "all",
	}

	_, err = utils.ExecuteCommand(ctx, logger, "katana", args...)
	// O erro é tratado pelo chamador.
	return err
}

// RunNuclei executa a ferramenta nuclei para varredura de vulnerabilidades.
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

	// Aplica o perfil de evasão
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
	// O erro é tratado pelo chamador.
	return err
}

// RunNikto executa a ferramenta nikto para varredura de servidores web.
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

// RunBBot executa a ferramenta bbot.
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

// RunFfuf executa a ferramenta ffuf para fuzzing.
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

// RunDirsearch executa a ferramenta dirsearch para fuzzing.
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
			hostOutputFile := filepath.Join(outputDir, sanitizedHost) // dirsearch adds .json

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

// RunFeroxbuster executa a ferramenta feroxbuster para fuzzing.
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
				"--no-state", // Evita criar arquivos .state
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

// RunGobuster executa a ferramenta gobuster para fuzzing de diretórios.
func RunGobuster(ctx context.Context, inputFile, wordlist, outputDir string, rateLimit int, logger *slog.Logger) error {
	logger.Info("Executing external command: gobuster")
	if !utils.CommandExists("gobuster") {
		logger.Warn("gobuster not found, skipping.", "help", "Install with: sudo apt install gobuster")
		return nil // Não é um erro fatal, apenas pula a ferramenta.
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
				"dir", // Modo de fuzzing de diretório
				"-u", h,
				"-w", wordlist,
				"-o", hostOutputFile,
				"-q", // Modo silencioso
				"--no-error",
				"-t", "50", // Threads
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

// RunDalfox executa a ferramenta dalfox para varredura de XSS.
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
		"--only-custom-payload", // Foca em payloads que têm maior chance de funcionar
	}

	_, err := utils.ExecuteCommand(ctx, logger, "dalfox", args...)
	// Dalfox pode retornar erros se não encontrar nada, então tratamos como um aviso.
	if err != nil {
		logger.Warn("Dalfox scan finished with a non-zero exit code.", "error", err)
	}
	return nil
}

// RunParamSpider executa a ferramenta paramspider para encontrar parâmetros.
func RunParamSpider(ctx context.Context, domain string, logger *slog.Logger) ([]string, error) {
	logger.Info("Executing external command: paramspider", "domain", domain)
	if !utils.CommandExists("paramspider") {
		logger.Warn("paramspider not found, skipping parameter discovery.", "help", "pip3 install git+https://github.com/devanshbatham/ParamSpider")
		return nil, nil
	}

	args := []string{
		"-d", domain, // Usa a flag -d para um único domínio
		"-s", // Usar -s para modo silencioso, que é mais comum.
	}

	// Executa o comando e captura a saída padrão (stdout).
	stdout, err := utils.ExecuteCommand(ctx, logger, "paramspider", args...)
	if err != nil {
		// Não retorna o erro para não quebrar o fluxo, pois a ferramenta pode falhar se não encontrar nada.
		// O erro já inclui o stderr, que é útil para depuração.
		return nil, fmt.Errorf("paramspider execution failed for domain %s: %w", domain, err)
	}

	// Filtra a saída para manter apenas as URLs válidas, removendo o banner da ferramenta.
	var validURLs []string
	for _, line := range strings.Split(stdout, "\n") {
		trimmedLine := strings.TrimSpace(line)
		// Adiciona uma verificação extra para garantir que a linha contenha o domínio alvo,
		// evitando que banners ou linhas de log sejam incluídos.
		if (strings.HasPrefix(trimmedLine, "http://") || strings.HasPrefix(trimmedLine, "https://")) && strings.Contains(trimmedLine, domain) {
			validURLs = append(validURLs, trimmedLine)
		}
	}

	return validURLs, nil
}

// RunEnum4linuxNG executa a ferramenta enum4linux-ng para enumeração SMB.
func RunEnum4linuxNG(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	logger.Info("Executing external command: enum4linux-ng", "target", target)
	if !utils.CommandExists("enum4linux-ng") {
		logger.Warn("enum4linux-ng not found, skipping SMB enumeration.", "help", "Install with: sudo apt install enum4linux-ng")
		return fmt.Errorf("enum4linux-ng not found in PATH")
	}

	// Argumentos comuns para enumeração SMB.
	// Você pode ajustar estes argumentos conforme a necessidade.
	args := []string{
		"-A", // Executa todas as enumerações simples (shares, users, groups, etc.)
		target,
	}

	// enum4linux-ng escreve no stdout, então precisamos capturar e salvar.
	output, err := utils.ExecuteCommand(ctx, logger, "enum4linux-ng", args...)
	if err != nil {
		// Retorna o erro, mas a função chamadora pode decidir se é fatal ou não.
		return fmt.Errorf("enum4linux-ng execution failed: %w", err)
	}

	// Salva a saída no arquivo especificado.
	return os.WriteFile(outputFile, []byte(output), 0644)
}

// RunWafw00f executa a ferramenta wafw00f para detecção de WAF.
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

// RunNaabu executa a ferramenta naabu para varredura de portas.
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
		"-top-ports", "1000", // Ajustado para 1000 para maior compatibilidade
		"-rate", "1000", // Ajustado para corresponder a um scan menos intenso
	}

	_, err := utils.ExecuteCommand(ctx, logger, "naabu", args...)
	return err
}

// RunDnsxInfra executa o dnsx para enumeração completa de registros DNS.
func RunDnsxInfra(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	logger.Info("Executing external command: dnsx (infra mode)", "target", target)
	if !utils.CommandExists("dnsx") {
		return fmt.Errorf("dnsx not found in PATH")
	}

	// CORREÇÃO: A flag '-d' no dnsx agora requer uma wordlist (-w).
	// Para consultar um único domínio, devemos passá-lo via stdin.
	args := []string{
		"-a", "-aaaa", "-cname", "-ns", "-txt", "-mx", "-soa", // Enumera todos os tipos de registro comuns
		"-resp", // Mostra a resposta do DNS
		"-silent",
	}

	// Cria o comando e define o stdin
	cmd := exec.CommandContext(ctx, "dnsx", args...)
	cmd.Stdin = strings.NewReader(target)

	// Executa o comando e captura a saída
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("command 'dnsx' failed: %v. Stderr: %s", err, stderr.String())
	}

	return os.WriteFile(outputFile, stdout.Bytes(), 0644)
}

// RunCloudEnum executa a ferramenta cloudenum.
func RunCloudEnum(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	toolName := "cloudenum"
	if !utils.CommandExists(toolName) {
		logger.Warn("cloudenum not found, skipping cloud enumeration.", "help", "Install from: https://github.com/initstring/cloud_enum")
		return nil
	}

	logger.Info("Executing external command: cloudenum", "target", target)

	args := []string{
		"-k", target, // Usa a palavra-chave do alvo para procurar em serviços de nuvem
		"-j", outputFile, // Salva a saída em formato JSON
		"-l", filepath.Join(filepath.Dir(outputFile), "cloudenum.log"), // Salva o log em um arquivo separado
	}

	_, err := utils.ExecuteCommand(ctx, logger, toolName, args...)
	if err != nil {
		// A ferramenta pode retornar erro se não encontrar nada, então tratamos como aviso.
		logger.Warn("cloudenum finished with an error, but this may be expected.", "error", err)
	}

	return nil
}

// RunSslScan executa a ferramenta sslscan.
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

// RunNmap executa um comando nmap genérico.
func RunNmap(ctx context.Context, target, outputFile string, logger *slog.Logger, args ...string) error {
	logger.Info("Executing external command: nmap", "target", target)
	if !utils.CommandExists("nmap") {
		return fmt.Errorf("nmap not found in PATH")
	}

	fullArgs := append(args, target)
	_, err := utils.ExecuteCommand(ctx, logger, "nmap", fullArgs...)
	return err
}

// RunCrackMapExec executa a ferramenta crackmapexec.
func RunCrackMapExec(ctx context.Context, protocol, target string, logger *slog.Logger) (string, error) {
	toolName := "crackmapexec"
	if !utils.CommandExists(toolName) {
		// Tenta com o alias 'cme'
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

// RunSipScan executa a ferramenta svmap para varredura de SIP/VoIP.
func RunSipScan(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	toolName := "svmap"
	if !utils.CommandExists(toolName) {
		logger.Warn("svmap not found, skipping SIP/VoIP scan.", "help", "Install with: sudo apt install sipvicious")
		return nil
	}

	logger.Info("Executing external command: svmap", "target", target)

	// svmap pode ser barulhento, então capturamos a saída.
	output, err := utils.ExecuteCommand(ctx, logger, toolName, target)
	if err != nil {
		// svmap pode retornar erro se não encontrar nada, então tratamos como aviso.
		logger.Warn("svmap finished with an error, but this may be expected.", "error", err)
	}

	if output != "" {
		return os.WriteFile(outputFile, []byte(output), 0644)
	}

	return nil
}

// RunNmapRpcScan executa uma varredura nmap focada em RPC.
func RunNmapRpcScan(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	logger.Info("Executing nmap RPC scan", "target", target)
	if !utils.CommandExists("nmap") {
		return fmt.Errorf("nmap not found in PATH")
	}

	args := []string{
		"-sV", "-p", "111,135", // Portas comuns de RPC
		"--script=rpcinfo",
		"-oN", outputFile,
		target,
	}

	_, err := utils.ExecuteCommand(ctx, logger, "nmap", args...)
	return err
}