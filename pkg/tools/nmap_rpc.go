package tools

import (
	"context"
	"log/slog"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)
func RunNmapRpcScan(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	args := []string{"-sV", "-p", "111,135", "--script=rpcinfo", "-oN", outputFile, target}
	_, err := utils.ExecuteCommand(ctx, logger, config.GetToolPath("nmap"), args...)
	return err
}
