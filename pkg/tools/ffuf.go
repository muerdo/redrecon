// pkg/tools/ffuf.go
package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunFfuf(
	ctx context.Context,
	inputFile, outputDir, wordlist, statusCodes string,
	rateLimit int,
	proxy string,
	headers []string,
	cookies string,
	logger *slog.Logger,
) error {
	toolPath := config.GetToolPath("ffuf")
	if toolPath == "" {
		return fmt.Errorf("ffuf not found")
	}

	wordlistPath := config.Cfg.Wordlists.Fuzzing
	if !strings.HasSuffix(wordlistPath, ".txt") {
		wordlistPath = "/usr/share/wordlists/dirb/common.txt"
		logger.Warn("Configured fuzzing wordlist is not a .txt file or is invalid. Using fallback.", "path", wordlistPath)
	}
	// If the wordlist parameter is provided, it overrides the config.
	if wordlist != "" {
		wordlistPath = wordlist
		if !strings.HasSuffix(wordlistPath, ".txt") {
			wordlistPath = "/usr/share/wordlists/dirb/common.txt"
			logger.Warn("Provided wordlist is not a .txt file or is invalid. Using fallback.", "path", wordlistPath)
		}
	}

	// Assume-se que inputFile já contém a palavra-chave FUZZ onde o fuzzing deve ocorrer.
	if inputFile == "" {
		return fmt.Errorf("ffuf requires an input URL (inputFile parameter) to fuzz")
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory %s: %w", outputDir, err)
	}
	outputFile := filepath.Join(outputDir, "ffuf_results.json")

	args := []string{
		"-u", inputFile,
		"-w", wordlistPath,
		"-o", outputFile,
		"-of", "json",
	}
	args = append(args, config.Cfg.Tools.Ffuf.ExtraArgs...)

	// Interactsh configuration
	if config.Cfg.Tools.Ffuf.InteractshURL != "" {
		args = append(args, "-H", fmt.Sprintf("X-Interactsh-URL: %s", config.Cfg.Tools.Ffuf.InteractshURL))
	}
	if config.Cfg.Tools.Ffuf.InteractshToken != "" {
		args = append(args, "-H", fmt.Sprintf("X-Interactsh-Token: %s", config.Cfg.Tools.Ffuf.InteractshToken))
	}

	if rateLimit > 0 {
		args = append(args, "-rate", fmt.Sprintf("%d", rateLimit))
	}

	if proxy != "" {
		args = append(args, "-x", proxy)
	}

	for _, h := range headers {
		args = append(args, "-H", h)
	}

	if cookies != "" {
		args = append(args, "-b", cookies)
	}

	logger.Info("Running Ffuf", "args", strings.Join(args, " "))
	_, err := utils.ExecuteCommand(ctx, logger, toolPath, args...)
	return err

}
