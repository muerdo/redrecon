package tools

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

func RunTestssl(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("failed to parse target URL for testssl: %w", err)
	}
	hostname := parsedURL.Hostname()
	args := []string{"--quiet", "--logfile", outputFile, hostname}
	_, err = utils.ExecuteCommand(ctx, logger, config.GetToolPath("testssl.sh"), args...)
	return err
}
