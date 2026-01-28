package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"redrecon/internal/config"
	"redrecon/pkg/utils"

	"gopkg.in/yaml.v2"
)

// RunNikto executa o Nikto com os argumentos fornecidos.
func RunNikto(ctx context.Context, targetList, outputFile, tempDir string, logger *slog.Logger, extraArgs ...string) (string, error) {
	logger.Info("Executing Nikto", "args", extraArgs)
	return utils.ExecuteCommand(ctx, logger, "nikto", extraArgs...)
}

func createSubfinderConfig(tempDir string) (string, error) {
	providerConfig := make(map[string][]string)
	keys := config.Cfg.APIKeys
	if keys.BinaryEdge != "" {
		providerConfig["binaryedge"] = []string{keys.BinaryEdge}
	}
	if keys.Censys != "" {
		providerConfig["censys"] = []string{keys.Censys}
	}
	if keys.Certspotter != "" {
		providerConfig["certspotter"] = []string{keys.Certspotter}
	}
	if keys.Chaos != "" {
		providerConfig["chaos"] = []string{keys.Chaos}
	}
	if keys.Github != "" {
		providerConfig["github"] = []string{keys.Github}
	}
	if keys.PassiveTotal != "" {
		providerConfig["passivetotal"] = []string{keys.PassiveTotal}
	}
	if keys.SecurityTrails != "" {
		providerConfig["securitytrails"] = []string{keys.SecurityTrails}
	}
	if keys.Shodan != "" {
		providerConfig["shodan"] = []string{keys.Shodan}
	}

	if len(providerConfig) == 0 {
		return "", nil
	}

	configFile, err := os.CreateTemp(tempDir, "subfinder-config-*.yaml")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary subfinder config file: %w", err)
	}
	defer configFile.Close()

	encoder := yaml.NewEncoder(configFile)
	err = encoder.Encode(providerConfig)
	if err != nil {
		return "", fmt.Errorf("failed to encode subfinder config to YAML: %w", err)
	}

	return configFile.Name(), nil
}
