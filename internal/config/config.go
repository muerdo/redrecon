package config

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"

	"github.com/spf13/viper"
)

type Config struct {
	APIKeys   APIKeys         `mapstructure:"api_keys"`
	Tools     ToolsConfig     `mapstructure:"tools"`
	Engine    EngineConfig    `yaml:"engine"`
	Recon     ReconConfig     `yaml:"recon"`
	Wordlists WordlistsConfig `yaml:"wordlists"`
	ToolPaths ToolPathsConfig `yaml:"tool_paths"`
}
type DiscordConfig struct {
	Enabled          bool   `mapstructure:"enabled"`
	Token            string `mapstructure:"token"`
	Prefix           string `mapstructure:"prefix"`
	WebhookURL       string `mapstructure:"webhook_url"`
	DefaultChannelID string `mapstructure:"default_channel_id"`
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
	MaxParallelTasks int           `yaml:"max_parallel_tasks"`
	Discord          DiscordConfig `yaml:"discord"`
	WAF              WAFConfig     `yaml:"waf"`
	TempDir          string        `yaml:"temp_dir"`
	
}
type WordlistsConfig struct {
    Subdomains string `mapstructure:"subdomains"`
    Fuzzing    string `mapstructure:"fuzzing"`
}

type ToolPathsConfig struct {
	Subfinder    string `yaml:"subfinder"`
	Httpx        string `yaml:"httpx"`
	ShuffleDNS   string `yaml:"shuffledns"`
	Katana       string `yaml:"katana"`
	Nuclei       string `yaml:"nuclei"`
	Nikto        string `yaml:"nikto"`
	Ffuf         string `yaml:"ffuf"`
	BBot         string `yaml:"bbot"`
	Dirsearch    string `yaml:"dirsearch"`
	Naabu        string `yaml:"naabu"`
	DNSValidator string `yaml:"dnsvalidator"`
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

// WAFProfile contém os parâmetros de evasão para um WAF específico.
type WAFProfile struct {
	RateLimit   int    `yaml:"rate_limit"`
	Concurrency int    `yaml:"concurrency"`
	Nuclei      string `yaml:"nuclei,omitempty"`
	Ffuf        string `yaml:"ffuf,omitempty"`
	Nikto       string `yaml:"nikto,omitempty"`
	ProxyFile   string `yaml:"proxy_file,omitempty"`
}

type WAFConfig struct {
	Enabled        bool                  `yaml:"enabled"`
	DefaultProfile WAFProfile            `yaml:"default_profile"`
	Profiles       map[string]WAFProfile `yaml:"profiles"`
}
var Cfg *Config

// GetTempDir retorna o diretório temporário configurado pelo usuário ou o padrão do sistema.
func GetTempDir() string {
	if Cfg.Engine.TempDir != "" {
		// Garante que o diretório base exista.
		if err := os.MkdirAll(Cfg.Engine.TempDir, 0755); err != nil {
			slog.Error("Failed to create custom temporary directory, falling back to system default", "path", Cfg.Engine.TempDir, "error", err)
			return os.TempDir()
		}
		return Cfg.Engine.TempDir
	}
	return os.TempDir()
}

// fileExistsAndIsExecutable verifica se um caminho existe e se é um arquivo executável.
func fileExistsAndIsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	// Verifica se é um arquivo regular e se tem permissão de execução para o usuário, grupo ou outros.
	return !info.IsDir() && (info.Mode()&0111 != 0)
}

// GetToolPath localiza uma ferramenta seguindo uma ordem de prioridade:
// 1. Caminho explícito no config.yaml.
// 2. Caminho encontrado na variável de ambiente PATH do sistema.
// 3. Busca em diretórios comuns (incluindo /mnt/dexter_storage/tools).
func GetToolPath(toolName string) string {
	// 1. Verifica se há um caminho personalizado no config.yaml
	var customPath string
	switch toolName {
	case "subfinder":
		customPath = Cfg.ToolPaths.Subfinder
	case "httpx":
		customPath = Cfg.ToolPaths.Httpx
	case "shuffledns":
		customPath = Cfg.ToolPaths.ShuffleDNS
	case "katana":
		customPath = Cfg.ToolPaths.Katana
	case "nuclei":
		customPath = Cfg.ToolPaths.Nuclei
	case "nikto":
		customPath = Cfg.ToolPaths.Nikto
	case "ffuf":
		customPath = Cfg.ToolPaths.Ffuf
	case "bbot":
		customPath = Cfg.ToolPaths.BBot
	case "dirsearch":
		customPath = Cfg.ToolPaths.Dirsearch
	case "dnsvalidator":
		customPath = Cfg.ToolPaths.DNSValidator
	case "naabu":
		customPath = Cfg.ToolPaths.Naabu
	}

	if customPath != "" {
		if fileExistsAndIsExecutable(customPath) {
			slog.Debug("Using tool from custom path specified in config", "tool", toolName, "path", customPath)
			return customPath
		}
		slog.Warn("Tool path specified in config.yaml not found or not executable, falling back to search", "tool", toolName, "path", customPath)
	}

	// 2. Procura no PATH do sistema
	if path, err := exec.LookPath(toolName); err == nil {
		slog.Debug("Found tool in system PATH", "tool", toolName, "path", path)
		return path
	}

	// 3. Procura em diretórios comuns
	homeDir, _ := os.UserHomeDir()
	commonDirs := []string{
		"/mnt/dexter_storage/backup/Tools", // Seu diretório!
		"/usr/local/bin",
		"/usr/bin",
		"/home/poliveira/go/bin",
	}
	if homeDir != "" {
		commonDirs = append(commonDirs, fmt.Sprintf("%s/go/bin", homeDir))
	}

	for _, dir := range commonDirs {
		path := fmt.Sprintf("%s/%s", dir, toolName)
		if fileExistsAndIsExecutable(path) {
			slog.Debug("Found tool in common directory", "tool", toolName, "path", path)
			return path
		}
	}

	// Se não encontrar em lugar nenhum, retorna o nome original e deixa o `exec` falhar.
	return toolName
}
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
