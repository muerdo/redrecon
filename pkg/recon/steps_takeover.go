package recon

import (
	"path/filepath"
	"redrecon/pkg/tools"
)

// stepRunSubdomainTakeover executa a verificação de subdomain takeover.
func stepRunSubdomainTakeover(state *reconState) error {
	state.logger.Info("--- Starting: Subdomain Takeover Scan ---")
	outputFile := filepath.Join(state.resultsPath, "subdomain_takeover.json")

	if err := tools.RunSubzy(state.ctx, state.liveSubdomainsFile, outputFile, state.logger); err != nil {
		state.logger.Error("Subdomain takeover scan failed", "error", err)
		return err // Retorna o erro para indicar falha na etapa.
	}
	return nil
}