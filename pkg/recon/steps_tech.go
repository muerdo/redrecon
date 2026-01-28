package recon

import (
	"fmt"
	"os"
	"path/filepath"
	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

// stepRunTechDetect executa a detecção de tecnologia nos hosts vivos.
func stepRunTechDetect(state *reconState) error {
	state.logger.Info("--- Starting: Technology Detection (httpx) ---")

	if !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Warn("Live subdomains file is empty or does not exist, skipping technology detection.", "file", state.liveSubdomainsFile)
		return nil
	}

	techFile := filepath.Join(state.resultsPath, "tech", "tech.json")
	if err := os.MkdirAll(filepath.Dir(techFile), 0755); err != nil {
		return fmt.Errorf("failed to create tech directory: %w", err)
	}

	// Executa o httpx com a flag de detecção de tecnologia ativada (último argumento 'true')
	var proxy string
	if state.proxyManager != nil {
		proxy = state.proxyManager.GetNextProxy()
	}

	err := tools.RunHttpx(
		state.ctx,
		state.liveSubdomainsFile, // -l
		techFile,                 // -o (tech.json)
		"",                       // liveHostsOutputFile (not needed here)
		state.tempDir,            // -srd
		state.followRedirects,    // -fr
		"",                       // -ports
		true,                     // -tech-detect
		proxy,                    // -proxy
		state.headers,            // -H
		state.cookies,            // -cookie
		state.username, state.password,
		state.logger,
	)

	if err != nil {
		state.MarkPartialFail("tech_detect", err)
		return nil // Não retorna erro fatal, apenas registra a falha parcial.
	}

	state.logger.Info("Technology detection completed.", "output_file", techFile)
	return nil
}
