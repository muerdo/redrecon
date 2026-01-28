package config

import (
	"log/slog"

	"github.com/spf13/viper"
)

// unmarshalConfig handles the unmarshaling of viper config into the Cfg struct
func unmarshalConfig() error {
	// Mapeia as variáveis de ambiente ANTES de fazer o Unmarshal.
	viper.AutomaticEnv()

	// Garante que a instância Cfg seja inicializada.
	Cfg = &Config{}

	// Desserializa a configuração lida pelo Viper para a struct Cfg.
	err := viper.Unmarshal(Cfg)
	if err != nil {
		return err
	}

	// Ensure Recon.Presets is initialized if not present in config
	if Cfg.Recon.Presets == nil {
		Cfg.Recon.Presets = make(map[string]ReconPresetConfig)
	}

	slog.Info("DEBUG: Viper Nuclei Templates", "templates", viper.Get("tools.nuclei.templates"))
	slog.Info("DEBUG: Viper All Keys", "keys", viper.AllKeys())
	slog.Info("DEBUG: Config Nuclei Templates", "templates", Cfg.Tools.Nuclei.Templates)

	return nil
}
