package recon

import (
	"path/filepath"
	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

// stepRunTechDetect executa a detecção de tecnologia nos hosts vivos.
func stepRunTechDetect(state *reconState) error {
	state.logger.Info("--- Starting: Technology Detection (httpx) ---")

	if !utils.FileExistsAndIsNotEmpty(state.liveSubdomainsFile) {
		state.logger.Warn("Live subdomains file is empty, skipping technology detection.")
		return nil
	}

	techFile := filepath.Join(state.resultsPath, "tech", "tech.json")

	// Executa o httpx com a flag de detecção de tecnologia ativada (último argumento 'true')
	err := tools.RunHttpx(
		state.ctx,
		state.liveSubdomainsFile, // Entrada
		techFile,                 // Saída
		"",                       // -path
		state.tempDir,            // -srd
		state.followRedirects,    // -fr
		"",                       // -ports
		true,                     // -tech-detect
		state.logger,
	)

	if err != nil {
		state.MarkPartialFail("tech_detect", err)
		return nil // Não retorna erro fatal, apenas registra a falha parcial.
	}

	state.logger.Info("Technology detection completed.", "output_file", techFile)
	return nil
}