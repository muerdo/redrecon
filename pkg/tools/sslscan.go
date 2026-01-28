package tools

import (
	"context"
	"log/slog"
	"os"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)
func RunSslScan(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	args := []string{"--show-certificate", "--no-colour", target}
	output, err := utils.ExecuteCommand(ctx, logger, config.GetToolPath("sslscan"), args...)
	if err == nil {
		os.WriteFile(outputFile, []byte(output), 0644)
	}
	return err
}
