package recon

import (
	"context"
	"log/slog"

	"redrecon/pkg/tools"
)

type passiveTool struct {
	name string
	run  func(context.Context, string, string, string, *slog.Logger) (string, error)
}

var passiveTools = []passiveTool{
	{name: "subfinder", run: tools.RunSubfinder},
	{name: "amass", run: tools.RunAmass},
	{name: "sublist3r", run: func(ctx context.Context, target, tempDir, proxy string, logger *slog.Logger) (string, error) {
		return tools.RunSublist3r(ctx, target, tempDir, logger)
	}},
	{name: "assetfinder", run: func(ctx context.Context, target, tempDir, proxy string, logger *slog.Logger) (string, error) {
		return tools.RunAssetfinder(ctx, target, tempDir, logger)
	}},
	{name: "chaos", run: func(ctx context.Context, target, tempDir, proxy string, logger *slog.Logger) (string, error) {
		return tools.RunChaos(ctx, target, tempDir, logger)
	}},
	{name: "certspotter", run: func(ctx context.Context, target, tempDir, proxy string, logger *slog.Logger) (string, error) {
		return tools.RunCertspotter(ctx, target, tempDir, logger)
	}},
}
