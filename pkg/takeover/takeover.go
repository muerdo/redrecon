package takeover

import (
	"context"
	"log/slog"

	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

// RunTakeoverScan executa a verificação de sequestro de subdomínio usando subzy.
func RunTakeoverScan(ctx context.Context, inputFile, outputFile string, logger *slog.Logger) error {
	logger.Info("Starting subdomain takeover scan with subzy.")

	if !utils.FileExistsAndIsNotEmpty(inputFile) {
		logger.Warn("Input file for takeover scan is empty, skipping.", "file", inputFile)
		return nil
	}

	// A função RunSubzy já existe no pacote tools.
	err := tools.RunSubzy(ctx, inputFile, outputFile, logger)
	return err
}