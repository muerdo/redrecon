package main

import (
	"fmt"
	"log/slog"
	"os"
	"redrecon/internal/config"

	"github.com/spf13/viper"
)

func main() {
	// Set up logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Load config
	configPath := "config.yaml"
	fmt.Printf("Loading config from: %s\n", configPath)

	if err := config.LoadConfigFromFile(configPath); err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		return
	}

	// Print Nuclei config
	fmt.Printf("Nuclei Enabled: %v\n", config.Cfg.Tools.Nuclei.Enabled)
	fmt.Printf("Nuclei Templates: %v\n", config.Cfg.Tools.Nuclei.Templates)
	fmt.Printf("Nuclei Templates Groups: %v\n", config.Cfg.Tools.Nuclei.TemplatesGroups)

	// Print Viper keys
	fmt.Printf("Viper Nuclei Templates: %v\n", viper.Get("tools.nuclei.templates"))
}
