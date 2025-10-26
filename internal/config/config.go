package config

import (
	"log/slog"

	"github.com/spf13/viper"
)

type Config struct {
	APIKeys   APIKeys         `mapstructure:"api_keys"`
	Tools     ToolsConfig     `mapstructure:"tools"`
	Engine    EngineConfig    `mapstructure:"engine"`
	Wordlists WordlistsConfig `mapstructure:"wordlists"`
	Recon     ReconConfig     `mapstructure:"recon"`
}

type DiscordConfig struct {
	Enabled    bool   `mapstructure:"enabled"`
	Token      string `mapstructure:"token"`
	Prefix     string `mapstructure:"prefix"`
	WebhookURL string `mapstructure:"webhook_url"`
}

type APIKeys struct {
	Github         string `mapstructure:"github"`
	Chaos          string `mapstructure:"chaos"`
	SecurityTrails string `mapstructure:"securitytrails"`
	Shodan         string `mapstructure:"shodan"`
	BinaryEdge     string `mapstructure:"binaryedge"`
	Censys         string `mapstructure:"censys"`
	Certspotter    string `mapstructure:"certspotter"`
	PassiveTotal   string `mapstructure:"passivetotal"`
}

type ToolsConfig struct {
	Nmap   string `mapstructure:"nmap"`
	Sqlmap string `mapstructure:"sqlmap"`
}

type EngineConfig struct {
	MaxParallelTasks int           `mapstructure:"max_parallel_tasks"`
	Discord          DiscordConfig `mapstructure:"discord"`
}
type WordlistsConfig struct {
    Subdomains string `mapstructure:"subdomains"`
    Fuzzing    string `mapstructure:"fuzzing"`
}

type ReconConfig struct {
	Nuclei NucleiConfig `mapstructure:"nuclei"`
	BBot   BBotConfig   `mapstructure:"bbot"`
}

type NucleiConfig struct {
	Templates []string `mapstructure:"templates"`
	OWASPTemplates   []string `mapstructure:"owasp_templates"`
	MonitorTemplates []string `mapstructure:"monitor_templates"`
}

type BBotConfig struct {
	Profile string `mapstructure:"profile"`
}

var Cfg *Config

func LoadConfig() (err error) {
	viper.SetDefault("engine.max_parallel_tasks", 5)
	viper.SetDefault("tools.nmap", "/usr/bin/nmap")
	viper.SetDefault("tools.sqlmap", "/usr/bin/sqlmap")

	viper.AddConfigPath(".")
	viper.AddConfigPath("$HOME/.config/redrecon")
	viper.AddConfigPath("/etc/redrecon/")
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")

	viper.AutomaticEnv()

	if errRead := viper.ReadInConfig(); errRead != nil {
		if _, ok := errRead.(viper.ConfigFileNotFoundError); ok {
			slog.Warn("Config file not found. Using defaults and environment variables.")
		} else {
			return errRead
		}
	}

	err = viper.Unmarshal(&Cfg)
	return
}
