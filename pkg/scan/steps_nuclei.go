package scan

import (
	"fmt"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/analysis"
	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

func stepRunNucleiScan(s *scanState) error {
	s.logger.Info("--- Starting: Vulnerability Scanning (Nuclei) ---")
	if !config.Cfg.Tools.Nuclei.Enabled {
		s.logger.Info("Nuclei is disabled in config, skipping.")
		return nil
	}

	if !utils.FileExistsAndIsNotEmpty(s.urlsFile) {
		s.logger.Warn("No URLs available for Nuclei scan, skipping.", "file", s.urlsFile)
		return nil
	}

	nucleiConfig := config.Cfg.Recon.Nuclei
	profile, ok := utils.GetActiveWAFProfile(s.logger, "", s.tempDir)
	rateLimit := nucleiConfig.RateLimit
	if rateLimit == 0 && ok {
		rateLimit = profile.RateLimit
	}
	concurrency := nucleiConfig.Concurrency
	if concurrency == 0 {
		concurrency = s.config.Engine.MaxParallelTasks
	}
	proxy := nucleiConfig.Proxy
	if proxy == "" && ok && profile.Proxy != "" {
		proxy = profile.Proxy
	}

	var templatesToRun []string
	if s.nucleiGroup != "" {
		// Se um grupo específico for fornecido, use-o.
		if groupTemplates, ok := nucleiConfig.TemplatesGroups[s.nucleiGroup]; ok {
			templatesToRun = groupTemplates
			s.logger.Info("Using specified Nuclei template group", "group", s.nucleiGroup)
		} else {
			s.logger.Warn("Specified Nuclei template group not found in config, falling back to default templates.", "group", s.nucleiGroup)
			templatesToRun = nucleiConfig.Templates // Fallback para os templates padrão
		}
	} else {
		// Se nenhum grupo for especificado, usa a lista de templates padrão.
		templatesToRun = nucleiConfig.Templates
	}

	extraArgs := nucleiConfig.ExtraArgs
	if rateLimit > 0 {
		extraArgs = append(extraArgs, "-rl", fmt.Sprintf("%d", rateLimit))
	}
	if concurrency > 0 {
		extraArgs = append(extraArgs, "-c", fmt.Sprintf("%d", concurrency))
	}
	nucleiOutputFile, err := tools.RunNuclei(s.ctx, s.urlsFile, strings.Join(templatesToRun, ","), proxy, s.logger, extraArgs)
	if err != nil {
		s.logger.Error("Nuclei scan step failed", "error", err)
		return err
	}

	// Update the state with the actual output file path
	s.nucleiScanFile = nucleiOutputFile

	// A análise agora acontece após a execução e com o caminho correto.
	if utils.FileExistsAndIsNotEmpty(s.nucleiScanFile) {
		s.parsedNucleiFindings, err = analysis.ParseNuclei(s.nucleiScanFile)
		if err != nil {
			s.logger.Error("Failed to parse Nuclei results", "error", err)
			// Não retorna erro, pois o scan em si foi bem-sucedido.
		}
	}
	return nil
}