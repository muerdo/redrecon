package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunParamSpider(ctx context.Context, inputFile, outputFile, tempDir string, logger *slog.Logger) error {
	t := config.Cfg.Tools.ParamSpider

	if !t.Enabled {
		return nil // Not an error, just disabled
	}

	paramspiderPath := config.GetToolPath("paramspider")
	if paramspiderPath == "" {
		return fmt.Errorf("paramspider tool path not configured")
	}

	profile, ok := utils.GetActiveWAFProfile(logger, "", tempDir)
	var proxy string
	if t.Proxy != "" {
		proxy = t.Proxy // Prioridade 1: Proxy específico da ferramenta
	} else if globalProxy := utils.GetGlobalProxy(); globalProxy != "" {
		proxy = globalProxy // Prioridade 2: Proxy global
	} else if ok && profile.Proxy != "" {
		proxy = profile.Proxy // Prioridade 3: Proxy do perfil WAF
	}

	// Arguments for the paramspider.py script
	args := []string{
		"-l", inputFile,
	}
	if proxy != "" {
		args = append(args, "--proxy", proxy)
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running ParamSpider", "command", paramspiderPath, "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, paramspiderPath, args...)

	if err != nil {
		return err
	}

	// The script now writes directly to outputFile, so no need to os.WriteFile here.
	return nil
}