package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"path/filepath"
	"os/exec"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type Config struct {
	APIKeys   APIKeys         `mapstructure:"api_keys"`
	Tools     ToolsConfig     `mapstructure:"tools"`
	Engine    EngineConfig    `yaml:"engine"`
	Recon     ReconConfig     `yaml:"recon"`
	Wordlists WordlistsConfig `yaml:"wordlists"`
	AI        AIConfig        `yaml:"ai"`
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

type AIConfig struct {
	Enabled        bool    `yaml:"enabled"`
	Provider       string  `yaml:"provider"`
	OpenAIAPIKey   string  `yaml:"openai_api_key"`
	DeepSeekAPIKey string `yaml:"deepseek_api_key"`
	Model          string  `yaml:"model"`
	Temperature    float64 `yaml:"temperature"`
	BaseURL        string  `yaml:"base_url"`
	APIKey         string  `yaml:"api_key"`
}
type WordlistsConfig struct {
    Subdomains string `mapstructure:"subdomains"`
    Fuzzing    string `mapstructure:"fuzzing"`
}

type ToolPathsConfig struct {
	Subfinder    string `yaml:"subfinder"`
	Httpx        string `yaml:"httpx"`
	Shuffledns   string `yaml:"shuffledns"`
	Katana       string `yaml:"katana"`
	Nuclei       string `yaml:"nuclei"`
	Nikto        string `yaml:"nikto"`
	Ffuf         string `yaml:"ffuf"`
	Bbot         string `yaml:"bbot"`
	Dirsearch    string `yaml:"dirsearch"`
	Sublist3r    string `yaml:"sublist3r"`
	Amass        string `yaml:"amass"`
	Wafw00f      string `yaml:"wafw00f"`
	Dalfox       string `yaml:"dalfox"`
	Assetfinder  string `yaml:"assetfinder"`
	Feroxbuster  string `yaml:"feroxbuster"`
	Paramspider  string `yaml:"paramspider"`
	Dnsx         string `yaml:"dnsx"`
	Naabu        string `yaml:"naabu"`
	Crackmapexec string `yaml:"crackmapexec"`
	Svmap        string `yaml:"svmap"`
	Cloudenum    string `yaml:"cloudenum"`
	Sslscan      string `yaml:"sslscan"`
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
	DefaultProxies []string              `yaml:"default_proxies,omitempty"`
	Profiles       map[string]WAFProfile `yaml:"profiles"`
}
var Cfg *Config

func GetTempDir() string {
	if Cfg.Engine.TempDir != "" {
		if err := os.MkdirAll(Cfg.Engine.TempDir, 0755); err != nil {
			slog.Error("Failed to create custom temporary directory, falling back to system default", "path", Cfg.Engine.TempDir, "error", err)
			return os.TempDir()
		}
		return Cfg.Engine.TempDir
	}
	return os.TempDir()
}

func GetProxyFile(profile WAFProfile, tempDir string) (string, bool) {
	if profile.ProxyFile != "" {
		if _, err := os.Stat(profile.ProxyFile); err == nil {
			slog.Debug("Using user-defined proxy file from profile.", "path", profile.ProxyFile)
			return profile.ProxyFile, true
		}
		slog.Warn("User-defined proxy file not found, falling back to defaults.", "path", profile.ProxyFile)
	}

	if len(Cfg.Engine.WAF.DefaultProxies) > 0 {
		slog.Debug("Creating temporary proxy file from default proxy list.")
		proxyFile, err := os.CreateTemp(tempDir, "default-proxies-*.txt")
		if err != nil {
			slog.Error("Failed to create temporary default proxy file", "error", err)
			return "", false
		}
		defer proxyFile.Close()

		_, err = proxyFile.WriteString(strings.Join(Cfg.Engine.WAF.DefaultProxies, "\n"))
		if err != nil {
			slog.Error("Failed to write to temporary default proxy file", "error", err)
			return "", false
		}
		return proxyFile.Name(), true
	}

	return "", false
}

func fileExistsAndIsExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && (info.Mode()&0111 != 0)
}

func GetToolPath(toolName string) string {
	var customPath string
	switch toolName {
	case "subfinder":
		customPath = Cfg.ToolPaths.Subfinder
	case "httpx":
		customPath = Cfg.ToolPaths.Httpx
	case "katana":
		customPath = Cfg.ToolPaths.Katana
	case "nuclei":
		customPath = Cfg.ToolPaths.Nuclei
	case "nikto":
		customPath = Cfg.ToolPaths.Nikto
	case "ffuf":
		customPath = Cfg.ToolPaths.Ffuf
	case "bbot":
		customPath = Cfg.ToolPaths.Bbot
	case "dirsearch":
		customPath = Cfg.ToolPaths.Dirsearch
	case "sublist3r":
		customPath = Cfg.ToolPaths.Sublist3r
	case "amass":
		customPath = Cfg.ToolPaths.Amass
	case "wafw00f":
		customPath = Cfg.ToolPaths.Wafw00f
	case "dalfox":
		customPath = Cfg.ToolPaths.Dalfox
	case "assetfinder":
		customPath = Cfg.ToolPaths.Assetfinder
	case "feroxbuster":
		customPath = Cfg.ToolPaths.Feroxbuster
	case "paramspider":
		customPath = Cfg.ToolPaths.Paramspider
	case "dnsx":
		customPath = Cfg.ToolPaths.Dnsx
	case "naabu":
		customPath = Cfg.ToolPaths.Naabu
	case "crackmapexec":
		customPath = Cfg.ToolPaths.Crackmapexec
	case "svmap":
		customPath = Cfg.ToolPaths.Svmap
	case "cloudenum":
		customPath = Cfg.ToolPaths.Cloudenum
	case "sslscan":
		customPath = Cfg.ToolPaths.Sslscan
	}

	if customPath != "" {
		if fileExistsAndIsExecutable(customPath) {
			slog.Debug("Using tool from custom path specified in config", "tool", toolName, "path", customPath)
			return customPath
		}
		slog.Warn("Tool path specified in config.yaml not found or not executable, falling back to search", "tool", toolName, "path", customPath)
	}

	if path, err := exec.LookPath(toolName); err == nil {
		slog.Debug("Found tool in system PATH", "tool", toolName, "path", path)
		return path
	}

	homeDir, _ := os.UserHomeDir()
	commonDirs := []string{
		"/mnt/dexter_storage/tools",
		"/usr/local/bin",
		"/usr/bin",
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

func UpdateToolPathsInConfig() {
	LoadConfig()

	toolsToCheck := []string{
		"subfinder", "httpx", "katana", "nuclei", "nikto", "ffuf",
		"bbot", "dirsearch", "naabu", "sublist3r", "amass", "wafw00f",
		"dalfox", "assetfinder", "feroxbuster", "paramspider", "dnsx", "jsbeautifier-go",
	}

	updated := false

	slog.Info("Buscando ferramentas no sistema para atualizar config.yaml...")
	for _, tool := range toolsToCheck {
		path, err := exec.LookPath(tool)
		if err != nil {
			slog.Warn("Ferramenta não encontrada no PATH", "tool", tool)
			continue
		}

		// Ferramenta encontrada, adiciona ao mapa.
		absPath, _ := filepath.Abs(path)
		
		switch tool {
		case "subfinder": Cfg.ToolPaths.Subfinder = absPath
		case "httpx": Cfg.ToolPaths.Httpx = absPath
		case "katana": Cfg.ToolPaths.Katana = absPath
		case "nuclei": Cfg.ToolPaths.Nuclei = absPath
		case "nikto": Cfg.ToolPaths.Nikto = absPath
		case "ffuf": Cfg.ToolPaths.Ffuf = absPath
		case "bbot": Cfg.ToolPaths.Bbot = absPath
		case "dirsearch": Cfg.ToolPaths.Dirsearch = absPath
		case "sublist3r": Cfg.ToolPaths.Sublist3r = absPath
		case "amass": Cfg.ToolPaths.Amass = absPath
		case "wafw00f": Cfg.ToolPaths.Wafw00f = absPath
		case "dalfox": Cfg.ToolPaths.Dalfox = absPath
		case "assetfinder": Cfg.ToolPaths.Assetfinder = absPath
		case "feroxbuster": Cfg.ToolPaths.Feroxbuster = absPath
		case "paramspider": Cfg.ToolPaths.Paramspider = absPath
		case "dnsx": Cfg.ToolPaths.Dnsx = absPath
		case "naabu": Cfg.ToolPaths.Naabu = absPath
		case "crackmapexec": Cfg.ToolPaths.Crackmapexec = absPath
		case "svmap": Cfg.ToolPaths.Svmap = absPath
		case "cloudenum": Cfg.ToolPaths.Cloudenum = absPath
		case "sslscan": Cfg.ToolPaths.Sslscan = absPath
		}
		slog.Info("Ferramenta encontrada e caminho adicionado ao config.yaml", "tool", tool, "path", absPath)
		updated = true
	}

	if !updated {
		slog.Info("Nenhuma nova ferramenta encontrada para adicionar ao 'config.yaml'.")
		return
	}

	configPath := "config.yaml"
	data, err := yaml.Marshal(&Cfg)
	if err != nil {
		slog.Error("Erro ao serializar o arquivo de configuração", "error", err)
		return
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		slog.Error("Erro ao salvar o arquivo 'config.yaml'", "error", err)
	}
	slog.Info("Arquivo 'config.yaml' atualizado com sucesso!")
}
