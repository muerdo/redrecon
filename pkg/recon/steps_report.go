
package recon

import (
	"path/filepath"

	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

// stepRunGenerateReport é um placeholder para a lógica de geração de relatório.
func stepRunGenerateReport(state *reconState) error {
	state.logger.Info("--- Starting: Report Generation ---")
	// A lógica de geração de relatório será implementada aqui.
	return nil
}

func stepRunMantra(state *reconState) error {
	state.logger.Info("--- Starting: Mantra Secret Discovery ---")

	if !utils.FileExistsAndIsNotEmpty(state.urlsFile) {
		state.logger.Warn("URLs file is empty, skipping Mantra scan.", "file", state.urlsFile)
		return nil
	}

	outputFile := filepath.Join(state.resultsPath, "mantra_findings.json")
	err := tools.RunMantra(state.ctx, state.urlsFile, outputFile, state.logger)
	if err != nil {
		state.MarkPartialFail("mantra", err)
		return nil // Not a fatal error
	}

	state.logger.Info("Mantra scan completed", "output_file", outputFile)
	return nil
}
