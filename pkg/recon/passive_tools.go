package recon

import (
	"context"
	"log/slog"

	"redrecon/pkg/tools"
)

type passiveTool struct {
	name string
	run  func(context.Context, string, string, *slog.Logger) (string, error)
}

var passiveTools = []passiveTool{
	{name: "subfinder", run: tools.RunSubfinder},
	{name: "amass", run: tools.RunAmass},
	{name: "sublist3r", run: tools.RunSublist3r},
	{name: "assetfinder", run: tools.RunAssetfinder},
	{name: "chaos", run: tools.RunChaos},
	{name: "certspotter", run: tools.RunCertspotter},
	
}
