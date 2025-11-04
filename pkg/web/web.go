package web

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"redrecon/internal/config"
	"redrecon/pkg/recon"
	"redrecon/pkg/utils"
	"redrecon/pkg/types"
	"redrecon/pkg/target"

	"github.com/gocolly/colly/v2"
)

// webState armazena o estado e os caminhos para uma operação de rastreamento web.
type webState struct {
	ctx         context.Context
	targetURL   string
	resultsPath string
	findingsFile string
	assetsPath  string
	logger      *slog.Logger
}

// StartWeb inicia o fluxo de trabalho de rastreamento e análise de um site.
func StartWeb(taskIdentifier, targetURL string, depth int, logger *slog.Logger) (string, []string, error) {
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
		ctx:         context.Background(),
		targetURL:   targetURL,
		resultsPath: resultsPath,
		assetsPath:  assetsPath,
		findingsFile: filepath.Join(resultsPath, "web_findings.txt"),
		logger:      logger,
	}

	// --- Etapa 1: Rastrear e baixar ativos ---
	logger.Info("Starting crawler to download assets...")
	c := colly.NewCollector(
		colly.Async(true),
		colly.MaxDepth(depth),
		colly.AllowedDomains(target.GetRootDomain(targetURL)), // Restringe o crawler ao domínio principal
	)

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

	if err != nil {
		logger.Error("Error during asset analysis", "error", err)
	}

	// --- Etapa 3: Gerar sumário ---
	summary := fmt.Sprintf("✅ **Web Crawl & Analysis Summary for: %s**\n\n", targetURL)
	summary += fmt.Sprintf("• **Crawl Depth:** %d\n", depth)
	findingsCount := utils.CountLines(state.findingsFile)
	summary += fmt.Sprintf("• **Findings (Secrets/Endpoints/Metadata):** %d\n", findingsCount)
	summary += fmt.Sprintf("\n*Full results and downloaded assets are in:* `%s`", resultsPath)

	return summary, []string{state.findingsFile}, nil
}