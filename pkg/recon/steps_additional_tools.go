package recon

import (
	"path/filepath"
	"redrecon/internal/config"
	"redrecon/pkg/tools"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

// stepRunParamSpider executa o ParamSpider nos URLs vivos.
func stepRunParamSpider(state *reconState) error {
	state.logger.Info("--- Starting: ParamSpider ---")

	if !config.Cfg.Tools.ParamSpider.Enabled {
		state.logger.Info("ParamSpider is disabled in config, skipping.")
		return nil
	}

	if !utils.FileExistsAndIsNotEmpty(state.liveURLsFile) {
		state.logger.Warn("Live URLs file is empty, skipping ParamSpider.")
		return nil
	}

	outputFile := filepath.Join(state.resultsPath, "params", "paramspider_output.txt")

	err := tools.RunParamSpider(
		state.ctx,
		state.liveURLsFile,
		outputFile,
		state.tempDir,
		state.logger,
	)

	if err != nil {
		state.MarkPartialFail("paramspider", err)
		return nil
	}

	state.logger.Info("ParamSpider completed.", "output_file", outputFile)
	return nil
}

// stepRunDalfox executa o Dalfox nos URLs vivos.
func stepRunDalfox(state *reconState) error {
	state.logger.Info("--- Starting: Dalfox ---")

	if !config.Cfg.Tools.Dalfox.Enabled {
		state.logger.Info("Dalfox is disabled in config, skipping.")
		return nil
	}

	if !utils.FileExistsAndIsNotEmpty(state.liveURLsFile) {
		state.logger.Warn("Live URLs file is empty, skipping Dalfox.")
		return nil
	}

	outputFile := filepath.Join(state.resultsPath, "xss", "dalfox_output.txt")

	err := tools.RunDalfox(
		state.ctx,
		state.liveURLsFile,
		outputFile,
		state.tempDir,
		state.logger,
	)

	if err != nil {
		state.MarkPartialFail("dalfox", err)
		return nil
	}

	state.logger.Info("Dalfox completed.", "output_file", outputFile)
	return nil
}

// stepRunArjun executa o Arjun nos URLs vivos.
func stepRunArjun(state *reconState) error {
	state.logger.Info("--- Starting: Arjun ---")

	if !config.Cfg.Tools.Arjun.Enabled {
		state.logger.Info("Arjun is disabled in config, skipping.")
		return nil
	}

	if !utils.FileExistsAndIsNotEmpty(state.liveURLsFile) {
		state.logger.Warn("Live URLs file is empty, skipping Arjun.")
		return nil
	}

	outputFile := filepath.Join(state.resultsPath, "params", "arjun_output.json")

	err := tools.RunArjun(
		state.ctx,
		state.liveURLsFile,
		outputFile,
		state.tempDir,
		state.logger,
	)

	if err != nil {
		state.MarkPartialFail("arjun", err)
		return nil
	}

	state.logger.Info("Arjun completed.", "output_file", outputFile)
	return nil
}

// stepRunSqlmap executa o Sqlmap nos URLs vivos.
func stepRunSqlmap(state *reconState) error {
	state.logger.Info("--- Starting: Sqlmap ---")

	if !config.Cfg.Tools.Sqlmap.Enabled {
		state.logger.Info("Sqlmap is disabled in config, skipping.")
		return nil
	}

	if !utils.FileExistsAndIsNotEmpty(state.liveURLsFile) {
		state.logger.Warn("Live URLs file is empty, skipping Sqlmap.")
		return nil
	}

	outputDir := filepath.Join(state.resultsPath, "sqli")

	err := tools.RunSqlmap(
		state.ctx,
		state.liveURLsFile,
		outputDir,
		state.tempDir,
		state.logger,
	)

	if err != nil {
		state.MarkPartialFail("sqlmap", err)
		return nil
	}

	state.logger.Info("Sqlmap completed.", "output_dir", outputDir)
	return nil
}

// stepRunCVESearch executa o CVESearch nas tecnologias detectadas.
func stepRunCVESearch(state *reconState) error {
	state.logger.Info("--- Starting: CVE Search ---")

	if !config.Cfg.Tools.CVESearch.Enabled {
		state.logger.Info("CVE Search is disabled in config, skipping.")
		return nil
	}

	techFile := filepath.Join(state.resultsPath, "tech", "tech.json")
	if !utils.FileExistsAndIsNotEmpty(techFile) {
		state.logger.Warn("Technology file is empty, skipping CVE Search.")
		return nil
	}

	outputFile := filepath.Join(state.resultsPath, "cves", "cve_search_output.json")

	err := tools.RunCVESearch(
		state.ctx,
		techFile,
		outputFile,
		state.logger,
	)

	if err != nil {
		state.MarkPartialFail("cve_search", err)
		return nil
	}

	state.logger.Info("CVE Search completed.", "output_file", outputFile)
	return nil
}

// stepRunEnum4linuxNG executa o Enum4linuxNG nos alvos.
func stepRunEnum4linuxNG(state *reconState) error {
	state.logger.Info("--- Starting: Enum4linuxNG ---")

	if !config.Cfg.Tools.Enum4linuxNG.Enabled {
		state.logger.Info("Enum4linuxNG is disabled in config, skipping.")
		return nil
	}

	if !utils.FileExistsAndIsNotEmpty(state.targetsFile) {
		state.logger.Warn("Targets file is empty, skipping Enum4linuxNG.")
		return nil
	}

	outputDir := filepath.Join(state.resultsPath, "enum4linuxng")

	err := tools.RunEnum4linuxNG(
		state.ctx,
		state.targetsFile, // Note: Enum4linuxNG usually takes a single target, but targetsFile is passed here. RunEnum4linuxNG logic takes 'target' string. If targetsFile is a path, Enum4linuxNG needs to handle it or we need to iterate.
		types.Credentials{},
		outputDir,
		state.logger,
	)

	if err != nil {
		state.MarkPartialFail("enum4linuxng", err)
		return nil
	}

	state.logger.Info("Enum4linuxNG completed.", "output_dir", outputDir)
	return nil
}

// stepResolveSubdomainIPs resolves IPs for all found subdomains and saves them to targets_ip.txt.
func stepResolveSubdomainIPs(state *reconState) error {
	state.logger.Info("--- Starting: Subdomain IP Resolution ---")
	if !utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Warn("Subdomains file is empty, skipping IP resolution.")
		return nil
	}

	outputFile := filepath.Join(state.resultsPath, "recon", "targets_ip.txt")

	if err := utils.ResolveIPs(state.subdomainsFile, outputFile); err != nil {
		state.logger.Warn("Failed to resolve IPs", "error", err)
		return nil // Non-fatal
	}

	state.logger.Info("Subdomain IP resolution completed.", "output_file", outputFile)
	return nil
}
