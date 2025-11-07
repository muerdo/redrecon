package tools

import (
	"context"
	"log/slog"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunCrackMapExec(ctx context.Context, protocol, target string, logger *slog.Logger) (string, error) {
	toolPath := config.GetToolPath("crackmapexec")
	args := []string{protocol, target}
	return utils.ExecuteCommand(ctx, logger, toolPath, args...)
}
