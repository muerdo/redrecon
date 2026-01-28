package tools

import (
	"context"
	"log/slog"
	"path/filepath"

	"redrecon/pkg/types"
)

// RunRDPCheck runs a credential check against RDP services using CrackMapExec.
// We prefer CME for recon/checking over xfreerdp which is a client.
func RunRDPCheck(ctx context.Context, targets []string, creds types.Credentials, outputDir string, logger *slog.Logger) error {
	logger.Info("Running RDP Credential Check via CrackMapExec...")
	logFile := filepath.Join(outputDir, "cme_rdp.log")

	// Reuse the existing RunCrackMapExec wrapper but specify "rdp" protocol
	return RunCrackMapExec(ctx, targets, "rdp", creds, logFile, logger)
}
