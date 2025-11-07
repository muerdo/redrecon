// pkg/recon/steps_live.go
package recon

import (
	"path/filepath"

	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

// stepRunLiveHosts valida hosts vivos
func stepRunLiveHosts(state *reconState) error {
	// PRIORIDADE 1: BBOT
	if utils.FileExistsAndIsNotEmpty(state.bbotLiveHostsFile) {
		state.liveSubdomainsFile = state.bbotLiveHostsFile
		state.logger.Info("Using BBOT for live hosts", "count", utils.CountLines(state.bbotLiveHostsFile))
		return nil
	}

	// PRIORIDADE 2: Httpx
	state.logger.Info("Falling back to Httpx for live hosts")

	if !utils.FileExistsAndIsNotEmpty(state.subdomainsFile) {
		state.logger.Warn("No subdomains to validate")
		return nil
	}

	outputFile := filepath.Join(state.resultsPath, "live", "httpx_live.txt")
	techFile := filepath.Join(state.resultsPath, "tech", "tech.json")

	// Etapa 1: Descobrir hosts vivos
	err := tools.RunHttpx(state.ctx, state.subdomainsFile, "", outputFile, state.tempDir, state.followRedirects, "", false, state.logger)
	if err != nil {
		state.logger.Warn("Httpx (live hosts) command finished with an error. This might be expected.", "error", err)
	}

	// Etapa 2: Detectar tecnologias nos hosts vivos
	err = tools.RunHttpx(
		state.ctx,
		outputFile, // Usa a saída da etapa anterior como entrada
		techFile,
		"", state.tempDir, state.followRedirects, "", true,
		state.logger,
	)
	if err != nil {
		state.logger.Warn("Httpx (tech-detect) command finished with a non-zero exit code.", "error", err)
	}

	if utils.FileExistsAndIsNotEmpty(outputFile) {
		state.liveSubdomainsFile = outputFile
		state.logger.Info("Httpx live hosts saved", "count", utils.CountLines(outputFile))
	}

	return nil
}