package tools

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunShuffledns(ctx context.Context, inputFile, outputFile, wordlist string, logger *slog.Logger) error {
	t := config.Cfg.Recon.Shuffledns
	toolPath := config.GetToolPath("shuffledns")
	if toolPath == "" || !t.Enabled {
		return fmt.Errorf("shuffledns disabled or not found")
	}

	args := []string{
		"-list", inputFile,
		"-w", wordlist,
		"-o", outputFile,
	}
	args = append(args, t.ExtraArgs...)

	logger.Info("Running Shuffledns", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err
}