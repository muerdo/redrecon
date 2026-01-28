package web

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"redrecon/internal/config"
	"redrecon/pkg/analysis"
	"redrecon/pkg/recon"
	"redrecon/pkg/target"
	"redrecon/pkg/tools"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"

	"github.com/gocolly/colly/v2"
	"gopkg.in/yaml.v2"
)

// webState armazena o estado e os caminhos para uma operação de rastreamento web.
type webState struct {
	ctx          context.Context
	targetURL    string
	resultsPath  string
	findingsFile string
	assetsPath   string
	logger       *slog.Logger
}

// StartWeb inicia o fluxo de trabalho de rastreamento e análise de um site.
func StartWeb(taskIdentifier, targetURL string, depth int, allowSubdomains bool, bbotPreset string, skipSteps []string, proxyManager *utils.ProxyManager, logger *slog.Logger) (string, []string, error) {
	logger.Info("Starting web crawl and analysis process", "target", targetURL, "depth", depth)

	sanitizedTaskIdentifier := utils.SanitizeTargetForPath(taskIdentifier)
	resultsPath := filepath.Join("results", sanitizedTaskIdentifier, "web")
	if err := os.MkdirAll(resultsPath, 0755); err != nil {
		return "", nil, fmt.Errorf("could not create web results directory: %w", err)
	}

	assetsPath := filepath.Join(resultsPath, "assets")
	if err := os.MkdirAll(assetsPath, 0755); err != nil {
		return "", nil, fmt.Errorf("could not create web assets directory: %w", err)
	}

	state := &webState{
		ctx:          context.Background(),
		targetURL:    targetURL,
		resultsPath:  resultsPath,
		assetsPath:   assetsPath,
		findingsFile: filepath.Join(resultsPath, "web_findings.txt"),
		logger:       logger,
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	// --- Etapa 1: Rastrear e baixar ativos ---
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		return "", nil, fmt.Errorf("could not parse target URL for crawler setup: %w", err)
	}

	logger.Info("Parsed URL and Hostname", "parsedURL", parsedURL.String(), "hostname", parsedURL.Hostname())

	allowedDomains := []string{parsedURL.Hostname()}
	if allowSubdomains {
		rootDomain := target.GetRootDomain(targetURL)
		if rootDomain != parsedURL.Hostname() {
			allowedDomains = append(allowedDomains, rootDomain)
		}
	}

	logger.Info("Starting crawler to download assets...")
	logger.Info("Allowed domains for crawler", "domains", allowedDomains)
	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(depth),
		colly.AllowedDomains(allowedDomains...),
	)

	if c == nil {
		return "", nil, fmt.Errorf("colly collector failed to initialize")
	}

	// Configura o proxy para o Colly, se disponível
	if proxyManager != nil {
		if proxyURL := proxyManager.GetNextProxy(); proxyURL != "" {
			if err := c.SetProxy(proxyURL); err != nil {
				logger.Warn("Failed to set proxy for crawler", "proxy", proxyURL, "error", err)
			}
		}
	}

	_ = c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: config.Cfg.Engine.MaxParallelTasks,
		Delay:       50 * time.Millisecond,
	})

	// Manipulador para baixar os ativos
	c.OnResponse(func(r *colly.Response) {
		// Sanitiza a URL para criar um nome de arquivo seguro
		sanitizedFilename := utils.SanitizeTargetForPath(r.Request.URL.String())
		// Adiciona uma extensão se não houver
		if filepath.Ext(sanitizedFilename) == "" {
			contentType := r.Headers.Get("Content-Type")
			if strings.Contains(contentType, "html") {
				sanitizedFilename += ".html"
			} else if strings.Contains(contentType, "javascript") {
				sanitizedFilename += ".js"
			}
		}

		filePath := filepath.Join(assetsPath, sanitizedFilename)
		if err := os.WriteFile(filePath, r.Body, 0644); err != nil {
			logger.Error("Failed to save asset", "path", filePath, "error", err)
		} else {
			logger.Debug("Saved asset for analysis", "path", filePath)
		}
	})

	// Encontra links para seguir
	c.OnHTML("a[href]", func(e *colly.HTMLElement) {
		_ = e.Request.Visit(e.Attr("href"))
	})

	// Inicia o rastreamento
	if err := c.Visit(targetURL); err != nil {
		logger.Error("Crawler failed to start", "url", targetURL, "error", err)
	}
	c.Wait()
	logger.Info("Asset download finished. Starting analysis.")

	// --- Etapa 1.5: Executar BBOT Web Scan (se bbotPreset for fornecido) ---
	if _, skip := skipSet["bbot"]; !skip && bbotPreset != "" {
		if err := stepRunBBotWeb(state, bbotPreset, proxyManager); err != nil {
			logger.Error("BBOT Web scan step failed", "error", err)
		}
	}

	// --- Etapa 2: Analisar os ativos baixados ---
	file, err := os.Create(state.findingsFile)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create web findings file: %w", err)
	}
	defer file.Close()
	writer := bufio.NewWriter(file)
	defer writer.Flush()

	var mu sync.Mutex
	var wg sync.WaitGroup

	err = filepath.Walk(assetsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			wg.Add(1)
			go func(filePath string) {
				defer wg.Done()
				content, readErr := os.ReadFile(filePath)
				if readErr != nil {
					logger.Warn("Failed to read asset for analysis", "path", filePath, "error", readErr)
					return
				}
				// Analisa JS e HTML para segredos e endpoints
				if strings.HasSuffix(filePath, ".js") || strings.HasSuffix(filePath, ".html") {
					secrets, endpoints := recon.AnalyzeContentForPatterns(string(content))
					if len(secrets) > 0 || len(endpoints) > 0 {
						findings := types.URLFindings{
							URL:       strings.TrimPrefix(filePath, assetsPath), // Usa o caminho relativo como identificador
							Secrets:   secrets,
							Endpoints: endpoints,
						}
						recon.WriteFindings(writer, &mu, "ASSET", findings, logger)
					}
				}

				// Analisa metadados de imagens e PDFs
				if recon.IsMetadataTarget(filePath) {
					// A função analyzeFileMetadata espera uma URL, então passamos o caminho do arquivo como um pseudo-URL
					recon.AnalyzeFileMetadata(state.ctx, &wg, "file://"+filePath, writer, &mu, logger)
				}
			}(path)
		}
		return nil
	})
	wg.Wait()

	// --- Etapa 2.1: Analisar todos os ativos com TruffleHog (executado uma vez) ---
	if _, skip := skipSet["trufflehog"]; !skip {
		logger.Info("Starting asset analysis with TruffleHog on the entire assets directory...")
		profile, ok := utils.GetActiveWAFProfile(logger, "", state.resultsPath)
		rateLimit := config.Cfg.Tools.TruffleHog.RateLimit
		if rateLimit == 0 && ok {
			rateLimit = profile.RateLimit
		}
		concurrency := config.Cfg.Tools.TruffleHog.Concurrency
		if concurrency == 0 {
			concurrency = config.Cfg.Engine.MaxParallelTasks
		}
		// Obtém o proxy do gerenciador
		var proxy string
		if proxyManager != nil {
			proxy = proxyManager.GetNextProxy()
		}

		if proxy == "" && ok && len(profile.Proxies) > 0 {
			proxy = profile.Proxies[0]
		} else if proxy == "" {
			proxy = config.Cfg.Tools.TruffleHog.Proxy
		}

		secretsFile := filepath.Join(state.assetsPath, "secrets_trufflehog.json")
		err = tools.RunTruffleHog(state.ctx, state.assetsPath, secretsFile, rateLimit, concurrency, proxy, logger)
		if err != nil {
			logger.Error("TruffleHog step failed", "error", err)
		} else if utils.FileExistsAndIsNotEmpty(secretsFile) {
			parsedSecrets, parseErr := analysis.ParseTruffleHog(secretsFile)
			if parseErr != nil {
				logger.Warn("TruffleHog parsing incomplete", "error", parseErr)
			} else {
				logger.Info("TruffleHog findings", "count", len(parsedSecrets))
				if len(parsedSecrets) > 0 {
					findings := types.URLFindings{
						URL:     "trufflehog://" + strings.TrimPrefix(state.assetsPath, state.resultsPath),
						Secrets: parsedSecrets, // Agora 'parsedSecrets' já é do tipo []types.Finding
					}
					mu.Lock()
					recon.WriteFindings(writer, &mu, "TRUFFLEHOG", findings, logger)
					mu.Unlock()
				}
			}
		}

		if err != nil {
			logger.Error("Error during asset analysis", "error", err)
		}
	}

	// --- Etapa 3: Gerar sumário ---
	summary := fmt.Sprintf("✅ **Web Crawl & Analysis Summary for: %s**\n\n", targetURL)
	summary += fmt.Sprintf("• **Crawl Depth:** %d\n", depth)
	findingsCount := utils.CountLines(state.findingsFile)
	summary += fmt.Sprintf("• **Findings (Secrets/Endpoints/Metadata):** %d\n", findingsCount)
	summary += fmt.Sprintf("\n*Full results and downloaded assets are in:* `%s`", resultsPath)

	return summary, []string{state.findingsFile}, nil
}

func stepRunBBotWeb(s *webState, bbotPreset string, pm *utils.ProxyManager) error {
	if !config.Cfg.Tools.Bbot.Enabled {
		s.logger.Info("BBOT is disabled in configuration. Skipping step.")
		return nil
	}

	if !utils.CommandExists("bbot") {
		s.logger.Error("bbot not installed or not executable. Check your PATH.", "tool", "bbot")
		return fmt.Errorf("bbot not found or not executable")
	}
	s.logger.Info("--- Starting: BBOT Web Scan ---")

	targetInput := s.targetURL
	// For web, the target is usually a single URL.

	// Load base BBot configuration from tools.bbot
	bbotConfig := config.Cfg.Tools.Bbot

	var currentPreset *config.BBotToolConfig
	if bbotPreset != "" {
		if preset, ok := config.Cfg.Recon.Presets[bbotPreset]; ok && preset.BBot != nil {
			currentPreset = preset.BBot
			s.logger.Info("Using BBot preset for Web scan", "preset", bbotPreset)
		} else {
			s.logger.Warn("BBot preset not found, falling back to default BBot configuration.", "preset", bbotPreset)
		}
	}

	// If a preset is active, merge its settings with the base bbotConfig
	if currentPreset != nil {
		if len(currentPreset.Presets) > 0 {
			bbotConfig.Presets = currentPreset.Presets
		}
		if len(currentPreset.Flags) > 0 {
			bbotConfig.Flags = currentPreset.Flags
		}
		if len(currentPreset.Modules) > 0 {
			bbotConfig.Modules = currentPreset.Modules
		}
		if len(currentPreset.OutputModules) > 0 {
			bbotConfig.OutputModules = currentPreset.OutputModules
		}
		if len(currentPreset.ExcludeModules) > 0 {
			bbotConfig.ExcludeModules = currentPreset.ExcludeModules
		}
		if len(currentPreset.Blacklist) > 0 {
			bbotConfig.Blacklist = currentPreset.Blacklist
		}
		if currentPreset.AllowDeadly {
			bbotConfig.AllowDeadly = true
		}
		if currentPreset.RateLimit > 0 {
			bbotConfig.RateLimit = currentPreset.RateLimit
		}
		if currentPreset.Concurrency > 0 {
			bbotConfig.Concurrency = currentPreset.Concurrency
		}
		// A lógica de proxy do gerenciador tem precedência
		if pm != nil {
			if proxy := pm.GetNextProxy(); proxy != "" {
				// Se o gerenciador tiver proxies, ele sobrescreve a configuração
				bbotConfig.Proxy = proxy
			}
		} else if currentPreset.Proxy != "" {
			bbotConfig.Proxy = currentPreset.Proxy
		}
		if len(currentPreset.ExtraArgs) > 0 {
			bbotConfig.ExtraArgs = currentPreset.ExtraArgs
		}
		if len(currentPreset.ConfigOverrides) > 0 {
			bbotConfig.ConfigOverrides = currentPreset.ConfigOverrides
		}
	}

	var extraArgs []string

	if len(bbotConfig.Presets) > 0 {
		for _, p := range bbotConfig.Presets {
			extraArgs = append(extraArgs, "-p", p)
		}
	}
	if len(bbotConfig.Flags) > 0 {
		for _, f := range bbotConfig.Flags {
			extraArgs = append(extraArgs, "-f", f)
		}
	}
	if len(bbotConfig.Modules) > 0 {
		extraArgs = append(extraArgs, "-m", strings.Join(bbotConfig.Modules, ","))
	}
	if len(bbotConfig.OutputModules) > 0 {
		extraArgs = append(extraArgs, "--output-module", strings.Join(bbotConfig.OutputModules, ","))
	}
	if len(bbotConfig.ExcludeModules) > 0 {
		extraArgs = append(extraArgs, "--exclude-module", strings.Join(bbotConfig.ExcludeModules, ","))
	}
	if len(bbotConfig.Blacklist) > 0 {
		for _, bl := range bbotConfig.Blacklist {
			extraArgs = append(extraArgs, "--blacklist", bl)
		}
	}
	if bbotConfig.AllowDeadly {
		extraArgs = append(extraArgs, "--allow-deadly")
	}
	if bbotConfig.RateLimit > 0 {
		extraArgs = append(extraArgs, "--rate-limit", fmt.Sprintf("%d", bbotConfig.RateLimit))
	}
	if bbotConfig.Concurrency > 0 {
		extraArgs = append(extraArgs, "--concurrency", fmt.Sprintf("%d", bbotConfig.Concurrency))
	}
	// Usa o proxy do gerenciador se disponível, senão usa o da configuração
	if pm != nil {
		if proxy := pm.GetNextProxy(); proxy != "" {
			bbotConfig.Proxy = proxy
		}
	}

	if bbotConfig.Proxy != "" {
		extraArgs = append(extraArgs, "--proxy", bbotConfig.Proxy)
	}
	if len(bbotConfig.ExtraArgs) > 0 {
		extraArgs = append(extraArgs, bbotConfig.ExtraArgs...)
	}

	// Handle config_overrides
	var tempConfigFile string
	if len(bbotConfig.ConfigOverrides) > 0 {
		var err error
		tempFile, err := os.CreateTemp(s.assetsPath, "bbot_config_override_*.yml") // Using assetsPath as temp dir
		if err != nil {
			return fmt.Errorf("failed to create temporary config override file: %w", err)
		}
		defer os.Remove(tempFile.Name())
		defer tempFile.Close()

		configBytes, err := yaml.Marshal(bbotConfig.ConfigOverrides)
		if err != nil {
			return fmt.Errorf("failed to marshal bbot config overrides: %w", err)
		}
		if _, err := tempFile.Write(configBytes); err != nil {
			return fmt.Errorf("failed to write bbot config overrides to temp file: %w", err)
		}
		tempConfigFile = tempFile.Name()
		extraArgs = append(extraArgs, "-c", tempConfigFile)
	}

	outputDir := filepath.Join(s.resultsPath, "bbot")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for bbot: %w", err)
	}

	jsonFile, err := tools.RunBBot(
		s.ctx,
		targetInput,
		"", // subdomainsFile (empty for now)
		outputDir,
		bbotConfig.AllowDeadly,
		bbotConfig.RateLimit,
		bbotConfig.Concurrency,
		bbotConfig.Proxy,
		s.logger,
		extraArgs...,
	)
	if err != nil {
		s.logger.Error("BBOT Web scan failed", "error", err)
		return nil // Not a fatal error
	}

	if jsonFile != "" && utils.FileExistsAndIsNotEmpty(jsonFile) {
		// Optionally parse BBot findings and add to Web state
		// For now, just log that it completed
		s.logger.Info("BBOT Web scan completed", "output_file", jsonFile)
	}

	return nil
}
