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



type Config struct { // Added a comment to force recompile
	APIKeys   APIKeys         `yaml:"api_keys"`   // FIX: Padroniza as tags para 'yaml' para garantir a desserialização correta.
	Tools     ToolsConfig     `yaml:"tools"`      // FIX: Padroniza as tags para 'yaml'.
	Engine    EngineConfig    `yaml:"engine"`     // Já estava correto.
	Recon     ReconConfig     `yaml:"recon"`      // Já estava correto.
	Wordlists WordlistsConfig `yaml:"wordlists"`  // Já estava correto.
	Monitor   MonitorConfig   `yaml:"monitor"`    // Já estava correto.
	AI        AIConfig        `yaml:"ai"`         // Já estava correto.
	Evasion   EvasionConfig   `yaml:"evasion"`    // Já estava correto.
	ToolPaths ToolPathsConfig `yaml:"tool_paths"` // Já estava correto.
	Metasploit MetasploitConfig `yaml:"metasploit"`
	Orchestration OrchestrationConfig `yaml:"orchestration"`
	Presets       PresetsConfig       `yaml:"presets"`
}

type EvasionConfig struct {
	Enabled         bool     `yaml:"enabled"`
	UseTor          bool     `yaml:"use_tor"`
	TorProxyAddress string   `yaml:"tor_proxy_address"` // Ex: "socks5://127.0.0.1:9050"
	UserAgents      []string `yaml:"user_agents"`
}
type DiscordConfig struct {
	Enabled          bool                  `yaml:"enabled"`
	Token            string                `yaml:"token"`
	Prefix           string                `yaml:"prefix"`
	WebhookURL       string                `yaml:"webhook_url"`
	DefaultChannelID string                `yaml:"default_channel_id"`
	Security         DiscordSecurityConfig `yaml:"security"`
}

type DiscordSecurityConfig struct {
	Enabled         bool     `yaml:"enabled"`
	WhitelistUsers  []string `yaml:"whitelist_users"`
	AllowedRoles    []string `yaml:"allowed_roles"`
	DenyMessage     string   `yaml:"deny_message"`
	LogUnauthorized bool     `yaml:"log_unauthorized"`
}

type APIKeys struct {
	Github         string `yaml:"github"`
	Chaos          string `yaml:"chaos"`
	SecurityTrails string `yaml:"securitytrails"`
	Shodan         string `yaml:"shodan"`
	BinaryEdge     string `yaml:"binaryedge"`
	Censys         string `yaml:"censys"`
	Certspotter    string `yaml:"certspotter"`
	PassiveTotal   string `yaml:"passivetotal"`
}

type ToolsConfig struct {
	Nmap           string                   `yaml:"nmap"`
	Sqlmap         SqlmapToolConfig         `yaml:"sqlmap"`
	Enum4linuxNG   Enum4linuxNGToolConfig `yaml:"enum4linux_ng"`
	Nikto          NiktoToolConfig          `yaml:"nikto"`
	Dirsearch      DirsearchToolConfig      `yaml:"dirsearch"`
	Feroxbuster    FeroxbusterToolConfig    `yaml:"feroxbuster"`
	Gobuster       GobusterToolConfig       `yaml:"gobuster"`
	Dalfox         DalfoxToolConfig         `yaml:"dalfox"`
	ParamSpider    ParamSpiderToolConfig    `yaml:"paramspider"`
	Subzy          SubzyToolConfig          `yaml:"subzy"`
	Arjun          ArjunToolConfig          `yaml:"arjun"`
	OWASP          OWASPToolConfig          `yaml:"owasp"` // Corrigido
	Wafw00f        Wafw00fToolConfig        `yaml:"wafw00f"` // Corrigido
	Assetfinder    AssetfinderToolConfig    `yaml:"assetfinder"`
	Bbot           BBotToolConfig         `yaml:"bbot"` // Corrigido
	Subfinder      SubfinderToolConfig    `yaml:"subfinder"` // Corrigido
	Httpx          HttpxToolConfig        `yaml:"httpx"` // Corrigido
	Katana         KatanaToolConfig       `yaml:"katana"`
	Nuclei         NucleiToolConfig       `yaml:"nuclei"`
	Sublist3r      Sublist3rToolConfig    `yaml:"sublist3r"`
	Amass          AmassToolConfig        `yaml:"amass"`
	Ffuf           FfufToolConfig         `yaml:"ffuf"`
	TruffleHog TruffleHogConfig `yaml:"trufflehog"`
}

type MetasploitConfig struct {
	Enabled      bool                `yaml:"enabled"`
	Host         string              `yaml:"host"`      // Ex: http://127.0.0.1:55553/api/
	User         string              `yaml:"user"`
	Pass         string              `yaml:"pass"`
	Timeout      string              `yaml:"timeout"`   // Ex: "2m"
	Retry        int                 `yaml:"retry"`
	AutoEscalate bool                `yaml:"auto_escalate"`
	Modules      map[string][]string `yaml:"modules"` // tech -> []module
	VulnerabilityModules map[string][]string `yaml:"vulnerability_modules"` // vulnerability_type -> []module
}

type OrchestrationConfig struct {
    AttackMate AttackMateConfig `yaml:"attackmate"`
    Sliver     SliverConfig     `yaml:"sliver"`
}

type PresetsConfig struct {
	BBotPresetsDir string `yaml:"bbot_presets_dir"`
}

type AttackMateConfig struct {
    Enabled   bool     `yaml:"enabled"`
    Path      string   `yaml:"path"`
    Playbooks []string `yaml:"playbooks"`
    RateLimit int      `yaml:"rate_limit"`
    Proxy     string   `yaml:"proxy"`
}

type SliverConfig struct {
    Enabled    bool   `yaml:"enabled"`
    Path       string `yaml:"path"`
    ServerAddr string `yaml:"server_addr"`
    Operator   string `yaml:"operator"`
    LHost      string `yaml:"lhost"`
    RateLimit  int    `yaml:"rate_limit"`
    // Note: RateLimit for Sliver is not directly used in the provided Implant function, but kept for consistency.
}
// Tool-specific configurations (newly added or corrected)
type SubfinderToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	All       bool     `yaml:"all,omitempty"`
	Threads   int      `yaml:"threads,omitempty"`
	Proxy     string   `yaml:"proxy,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type SqlmapToolConfig struct {
	Enabled bool   `yaml:"enabled"`
	Proxy   string `yaml:"proxy,omitempty"`
	Level   int    `yaml:"level,omitempty"` // 1-5
	Risk    int    `yaml:"risk,omitempty"`  // 1-3
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type TruffleHogConfig struct {
	Enabled          bool     `yaml:"enabled"`          // Liga/desliga
	Path             string   `yaml:"path,omitempty"`   // Diretório de arquivos a escanear (herda de resultsPath se vazio)
	Entropy          bool     `yaml:"entropy"`          // Ativa detecção por entropia
	Rules            string   `yaml:"rules,omitempty"`  // Path para custom rules (--rules)
	NoVerify         bool     `yaml:"no_verify"`        // Pula verificação de secrets
	Proxy            string   `yaml:"proxy"`            // Proxy para verificações HTTP
	RateLimit        int      `yaml:"rate_limit"`       // 0 = herda de WAF
	Concurrency      int      `yaml:"concurrency"`      // 0 = herda de engine.max_parallel_tasks
	JSONOutput       bool     `yaml:"json_output"`      // Força JSON para parsing
	ExtraArgs        []string `yaml:"extra_args"`       // Flags customizadas (ex.: "--only-verified")
}

type ProxyConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"` // Ex: "http://127.0.0.1:8080" ou "socks5://127.0.0.1:9050"
}

type EngineConfig struct {
	MaxParallelTasks int           `yaml:"max_parallel_tasks"`
	Discord          DiscordConfig `yaml:"discord"`
	WAF              WAFConfig     `yaml:"waf"`
	TempDir          string        `yaml:"temp_dir"`
	Proxy            ProxyConfig   `yaml:"proxy"`
	
}

type AIConfig struct {
	Enabled        bool    `yaml:"enabled"`          // FIX: Padroniza as tags para 'yaml' para garantir a desserialização correta.
	Provider       string  `yaml:"provider"`         // FIX: Padroniza as tags para 'yaml'.
	OpenAIAPIKey   string  `yaml:"openai_api_key"`   // FIX: Padroniza as tags para 'yaml'.
	DeepSeekAPIKey string  `yaml:"deepseek_api_key"` // FIX: Padroniza as tags para 'yaml'.
	Model          string  `yaml:"model"`            // FIX: Padroniza as tags para 'yaml'.
	Temperature    float64 `yaml:"temperature"`      // FIX: Padroniza as tags para 'yaml'.
	BaseURL        string  `yaml:"base_url"`         // FIX: Padroniza as tags para 'yaml'.
	APIKey         string  `yaml:"api_key"`          // FIX: Padroniza as tags para 'yaml'.
}
type WordlistsConfig struct {
    Subdomains string `yaml:"subdomains"`
    Fuzzing    string `yaml:"fuzzing"`
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
	Sqlmap       string `yaml:"sqlmap"`
	CVESearch    string `yaml:"cvesearch"`
	Enum4linuxng string `yaml:"enum4linuxng"`
	Attackmate   string `yaml:"attackmate"`
	Sliver       string `yaml:"sliver"`
}
type DnsxToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	InfraArgs []string `yaml:"infra_args"`
	ExtraArgs []string `yaml:"extra_args"`
}

type MonitorConfig struct {
	Enabled          bool       `yaml:"enabled"`
	Frequency        string     `yaml:"frequency"`         // Frequência padrão (ex: "6h")
	BbotRotation     [][]string `yaml:"bbot_rotation"`     // Lista de grupos de módulos do bbot para alternar
	NucleiLFRGroup   string     `yaml:"nuclei_lfr_group"`  // Nome do grupo de templates do Nuclei para "low-hanging fruits"
	NotifyOnNew      bool       `yaml:"notify_on_new"`     // Enviar notificação no Discord para novos achados
}

type WebConfig struct {
	Enabled      bool   `yaml:"enabled"`      // Liga/desliga
	Depth        int    `yaml:"depth"`        // Max depth para crawl
	Concurrency  int    `yaml:"concurrency"`  // Goroutines para análise (0 = MaxParallelTasks)
	Proxy        string `yaml:"proxy"`        // Proxy para crawl
	ExtraArgs    []string `yaml:"extra_args"`   // Para crawler custom
}
type ReconPresetConfig struct {
	BBot *BBotToolConfig `yaml:"bbot"`
}

type ReconConfig struct {
	Nuclei         NucleiConfig         `yaml:"nuclei"`
	BBot           BBotToolConfig       `yaml:"bbot"` // Já existente
	Subfinder      SubfinderToolConfig  `yaml:"subfinder"`
	Amass          AmassToolConfig      `yaml:"amass"`
	Sublist3r      Sublist3rToolConfig  `yaml:"sublist3r"`
	Assetfinder    AssetfinderToolConfig `yaml:"assetfinder"`
	Chaos          ChaosToolConfig      `yaml:"chaos"`
	Certspotter    CertspotterToolConfig `yaml:"certspotter"`
	Shuffledns     ShufflednsToolConfig `yaml:"shuffledns"`
	Crt            CrtToolConfig        `yaml:"crt"`
	CrtDb          CrtDbToolConfig      `yaml:"crt_db"`
	Httpx          HttpxToolConfig      `yaml:"httpx"`
	Katana         KatanaToolConfig     `yaml:"katana"`
	Gau            GauToolConfig        `yaml:"gau"`
	Kiterunner     KiterunnerToolConfig `yaml:"kiterunner"`
	Wafw00f        Wafw00fToolConfig    `yaml:"wafw00f"`
	CVESearch      CVESearchToolConfig  `yaml:"cve_search"`
	Dirsearch      DirsearchToolConfig  `yaml:"dirsearch"`
	Feroxbuster    FeroxbusterToolConfig `yaml:"feroxbuster"`
	Gobuster       GobusterToolConfig   `yaml:"gobuster"`	
	Nikto          NiktoToolConfig      `yaml:"nikto"`
	Dnsx           DnsxToolConfig       `yaml:"dnsx"`
	Naabu          NaabuToolConfig      `yaml:"naabu"`
	Web WebConfig `yaml:"web"`
	Presets        map[string]ReconPresetConfig `yaml:"presets"`
}

type NucleiConfig struct {
	Templates        []string `yaml:"templates"`        // Diretórios/arquivos de templates (ex.: "cves/", "technologies/")
	OWASPTemplates   []string `yaml:"owasp_templates"`  // Templates OWASP específicos
	MonitorTemplates []string `yaml:"monitor_templates"` // Para monitoramento contínuo
	Proxy            string   `yaml:"proxy"`            // Proxy para evasão (herda de WAF se vazio)
	RateLimit        int      `yaml:"rate_limit"`       // 0 = herda de WAF
	Concurrency      int      `yaml:"concurrency"`      // 0 = herda de engine.max_parallel_tasks
	TemplatesGroups  map[string][]string `yaml:"templates_groups"` // Grupos de templates pré-definidos (ex: light, full)
	Aggressive       bool     `yaml:"aggressive"`       // Ativa templates mais invasivos
	Headless         bool     `yaml:"headless"`         // Modo sem interatividade
	JSONOutput       bool     `yaml:"json_output"`      // Força output JSON para parsing
	UpdateTemplates  bool     `yaml:"update_templates"`   // Adicionado para corresponder ao uso
	ExtraArgs        []string `yaml:"extra_args"`       // Flags customizadas (ex.: "-severity critical")
	InteractshURL    string   `yaml:"interactsh_url,omitempty"`
	InteractshToken  string   `yaml:"interactsh_token,omitempty"`
	Silent           bool     `yaml:"silent,omitempty"`
	Timeout          int      `yaml:"timeout,omitempty"`
	OutputDir        string   `yaml:"output_dir,omitempty"`
}

type BBotToolConfig struct {
	Enabled          bool              `yaml:"enabled"`           // liga/desliga o BBOT
	Presets          []string          `yaml:"presets"`           // -p preset1 preset2
	Flags            []string          `yaml:"flags"`             // -f subdomain-enum,web-basic
	Modules          []string          `yaml:"modules"`           // módulos individuais
	OutputModules    []string          `yaml:"output_modules"`    // txt, json, neo4j, etc.
	Include          []string          `yaml:"include,omitempty"`
	ExcludeModules   []string          `yaml:"exclude_modules,omitempty"`
	Blacklist        []string          `yaml:"blacklist,omitempty"`
	RateLimit        int               `yaml:"rate_limit"`        // 0 = usa perfil WAF
	Concurrency      int               `yaml:"concurrency"`       // 0 = usa engine.max_parallel_tasks
	Proxy            string            `yaml:"proxy"`             // vazio = usa perfil WAF
	AllowDeadly      bool              `yaml:"allow_deadly"`      // --allow-deadly
	ExtraArgs        []string          `yaml:"extra_args"`        // qualquer flag desconhecida
	ModulesGroups    map[string][]string `yaml:"modules_groups"`    // Grupos de módulos pré-definidos (ex: light, full)
	ConfigOverrides  map[string]any    `yaml:"config_overrides"` // sobrescreve bbot.yml interno
	ListModules      bool              `yaml:"list_modules"`      // Se true, lista os módulos do BBOT no início
}

// Default BBOT modules (extracted from https://www.blacklanternsecurity.com/bbot/Stable/modules/list_of_modules/)
var DefaultBBotModules = []string{
	"ajaxpro", "aspnet_bin_exposure", "baddns", "bucket_amazon", "dnsbrute", "ffuf", "git", "httpx", "nuclei", "portscan", "retirejs", "wafw00f", "wpscan",
	"anubisdb", "asn", "builtwith", "chaos", "crt", "dehashed", "fullhunt", "github_codesearch", "hunterio", "shodan_dns", "wayback",
	"asset_inventory", "csv", "discord", "json", "nmap_xml", "slack", "stdout", "web_report",
	"cloudcheck", "dnsresolve", "aggregate", "speculate",
}
type Enum4linuxNGToolConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Domain     string `yaml:"domain,omitempty"`
	Username   string `yaml:"username,omitempty"`
	Password   string `yaml:"password,omitempty"`
	Threads    int    `yaml:"threads,omitempty"`
	RateLimit  int    `yaml:"rate_limit,omitempty"`
	Flags      []string `yaml:"flags,omitempty"`
	Proxy      string `yaml:"proxy,omitempty"`
}
type ChaosToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	APIKey    string   `yaml:"api_key,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type CertspotterToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type FfufToolConfig struct {
	Enabled   bool   `yaml:"enabled"`
	RateLimit int    `yaml:"rate_limit"` // 0 significa usar o rate_limit do perfil WAF, caso contrário, sobrescreve
	    Proxy     string `yaml:"proxy"`      // Vazio significa usar o proxy do perfil WAF, caso contrário, sobrescreve
		ExtraArgs []string `yaml:"extra_args,omitempty"`
		InteractshURL    string   `yaml:"interactsh_url,omitempty"`
		InteractshToken  string   `yaml:"interactsh_token,omitempty"`
	}

type GauToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type KiterunnerToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type ShufflednsToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Wordlist  string   `yaml:"wordlist,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type CrtToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type CrtDbToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type KatanaToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Depth     int      `yaml:"depth,omitempty"` // Default to 5 for deep crawl
	Proxy     string   `yaml:"proxy,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"` // Add -jc and -known-files all by default
}

type NucleiToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type HttpxToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	FollowRedirects bool `yaml:"follow_redirects,omitempty"`
	Threads   int      `yaml:"threads,omitempty"`
	Proxy     string   `yaml:"proxy,omitempty"`
	VulnTemplates []string `yaml:"vuln_templates,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}


type DirsearchToolConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Threads    int      `yaml:"threads,omitempty"`
	Proxy      string   `yaml:"proxy,omitempty"`
	ExtraArgs  []string `yaml:"extra_args,omitempty"`
}
type FeroxbusterToolConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Threads    int      `yaml:"threads,omitempty"`
	Proxy      string   `yaml:"proxy,omitempty"`
	ExtraArgs  []string `yaml:"extra_args,omitempty"`
}
type WAFProfile struct {
	RateLimit  int      `yaml:"rate_limit"`
	Concurrency int     `yaml:"concurrency"`
	ProxyFile  string   `yaml:"proxy_file"`
	Proxy      string   `yaml:"proxy,omitempty"`
	Proxies    []string `yaml:"default_proxies,omitempty"`
}
type NiktoToolConfig struct {
	Enabled         bool     `yaml:"enabled"`
	OutputFile      string   `yaml:"output_file,omitempty"`
	OutputFormat    string   `yaml:"output_format,omitempty"`
	Tuning          string   `yaml:"tuning,omitempty"`
	PauseSeconds    float64  `yaml:"pause_seconds,omitempty"`
	Proxy           string   `yaml:"proxy,omitempty"`
	MaxTime         int      `yaml:"maxtime,omitempty"`      // Em segundos
	Evasion         string   `yaml:"evasion,omitempty"`      // Ex: "1"
	Mutate          string   `yaml:"mutate,omitempty"`       // Ex: "1,2,3"
	FollowRedirects bool     `yaml:"follow_redirects"`
	Timeout         int      `yaml:"timeout,omitempty"`      // Em segundos
	ExtraArgs       []string `yaml:"extra_args,omitempty"`
}
type AmassToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Passive   bool     `yaml:"passive,omitempty"`
	Timeout   int      `yaml:"timeout,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type NaabuToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Threads   int      `yaml:"threads,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type Sublist3rToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Threads   int      `yaml:"threads,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type AssetfinderToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type GobusterToolConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Threads    int      `yaml:"threads,omitempty"`
	Proxy      string   `yaml:"proxy,omitempty"`
	ExtraArgs  []string `yaml:"extra_args,omitempty"`
	InteractshURL    string   `yaml:"interactsh_url,omitempty"`
	InteractshToken  string   `yaml:"interactsh_token,omitempty"`
}

type DalfoxToolConfig struct {
	Enabled       bool     `yaml:"enabled"`
	Proxy         string   `yaml:"proxy,omitempty"`
	ExtraArgs     []string `yaml:"extra_args,omitempty"`
	InteractshURL string   `yaml:"interactsh_url,omitempty"`
	InteractshToken string `yaml:"interactsh_token,omitempty"`
}

type ParamSpiderToolConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Proxy      string   `yaml:"proxy,omitempty"`
	ExtraArgs  []string `yaml:"extra_args,omitempty"`
}

type SubzyToolConfig struct {
	Enabled    bool     `yaml:"enabled"`
	ExtraArgs  []string `yaml:"extra_args,omitempty"`
}

type ArjunToolConfig struct {
	Enabled    bool     `yaml:"enabled"`
	ExtraArgs  []string `yaml:"extra_args,omitempty"`
}

type OWASPToolConfig struct {
	Enabled bool `yaml:"enabled"`
}

type Wafw00fToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Proxy     string   `yaml:"proxy,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type CVESearchToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
// A declaração duplicada de Enum4linuxNGToolConfig foi removida.
type WAFConfig struct {
	Enabled        bool                           `yaml:"enabled"`
	DefaultProfile string                         `yaml:"default_profile"` // ← STRING
	Profiles       map[string]WAFProfile          `yaml:"profiles"`
	DefaultProxies []string              `yaml:"default_proxies,omitempty"`
	TorProxy       string                `yaml:"tor_proxy,omitempty"`
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
func (c *ReconConfig) IsEnabled(tool string) bool {
	switch tool {
	case "subfinder":
		return c.Subfinder.Enabled
	case "amass":
		return c.Amass.Enabled
	case "sublist3r":
		return c.Sublist3r.Enabled
	case "assetfinder":
		return c.Assetfinder.Enabled
	case "chaos":
		return c.Chaos.Enabled
	case "certspotter":
		return c.Certspotter.Enabled
		case "shuffledns":
		return c.Shuffledns.Enabled
	case "crt":
		return c.Crt.Enabled
	case "crt_db":
		return c.CrtDb.Enabled
		case "httpx":
		return c.Httpx.Enabled
	case "katana":
		return c.Katana.Enabled
	case "gau":
		return c.Gau.Enabled
	case "kiterunner":
		return c.Kiterunner.Enabled
	case "wafw00f":
		return c.Wafw00f.Enabled
		case "cve_search":
		return c.CVESearch.Enabled	
	case "dirsearch":
		return c.Dirsearch.Enabled
	case "feroxbuster":
		return c.Feroxbuster.Enabled
	case "gobuster":
		return c.Gobuster.Enabled
	case "naabu":
		return c.Naabu.Enabled
	case "bbot":
		return c.BBot.Enabled		
	case "arjun":
		return Cfg.Tools.Arjun.Enabled
	case "paramspider":
		return Cfg.Tools.ParamSpider.Enabled
	case "dalfox":
		return Cfg.Tools.Dalfox.Enabled
	case "sqlmap":
		return Cfg.Tools.Sqlmap.Enabled
	case "enum4linux_ng":
		return Cfg.Tools.Enum4linuxNG.Enabled
	default:
		return false
	}
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
	case "sqlmap":
		customPath = Cfg.ToolPaths.Sqlmap
	case "cvesearch":
		customPath = Cfg.ToolPaths.CVESearch
	case "enum4linuxng":
		customPath = Cfg.ToolPaths.Enum4linuxng
	case "attackmate":
		customPath = Cfg.Orchestration.AttackMate.Path
	case "sliver":
		customPath = Cfg.Orchestration.Sliver.Path
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

// GetAllToolKeys retorna uma lista de todas as chaves de ferramentas conhecidas.
// Isso é usado pelo comando 'check' para verificar se todas as ferramentas estão instaladas.
func GetAllToolKeys() []string {
	return []string{
		"subfinder", "httpx", "shuffledns", "katana", "nuclei", "nikto", "ffuf",
		"bbot", "dirsearch", "sublist3r", "amass", "wafw00f", "dalfox",
		"assetfinder", "feroxbuster", "paramspider", "dnsx", "naabu",
		"crackmapexec", "svmap", "cloudenum", "sslscan", "sqlmap",
		"cvesearch", "enum4linuxng", "attackmate", "sliver", "subzy",
		// Adicione outras ferramentas aqui conforme elas são adicionadas ao ToolPathsConfig
	}
}


// LoadConfigFromFile carrega a configuração de um arquivo específico.
func LoadConfigFromFile(filePath string) error {
	viper.SetConfigFile(filePath)
	viper.SetConfigType("yaml")

	if err := viper.ReadInConfig(); err != nil {
		return fmt.Errorf("falha ao ler o arquivo de configuração especificado '%s': %w", filePath, err)
	}

	// FIX: Inicializa Cfg antes de unmarshal para garantir que a estrutura seja alocada.
	Cfg = &Config{}
	err := viper.Unmarshal(Cfg)
	if err != nil {
		return err
	}

	// Ensure Recon.Presets is initialized if not present in config
	if Cfg.Recon.Presets == nil {
		Cfg.Recon.Presets = make(map[string]ReconPresetConfig)
	}
	return nil
}

// LoadConfig procura e carrega a configuração de caminhos padrão.
func LoadConfig(configPaths ...string) error {
	viper.SetDefault("engine.max_parallel_tasks", 5)
	viper.SetDefault("tools.nmap", "/usr/bin/nmap")
	viper.SetDefault("tools.sqlmap", "/usr/bin/sqlmap")

	// Set default for BBOT modules and list_modules
	viper.SetDefault("recon.bbot.list_modules", true)
	viper.SetDefault("recon.bbot.modules", DefaultBBotModules)

	viper.SetDefault("metasploit.enabled", true)
	viper.SetDefault("orchestration.attackmate.enabled", true)
	viper.SetDefault("orchestration.sliver.enabled", true)
	viper.SetDefault("evasion.enabled", true)
	viper.SetDefault("discord.enabled", true)
	viper.SetDefault("discord.security.enabled", true)
	viper.SetDefault("ai.enabled", true)
	viper.SetDefault("monitor.enabled", true)
	viper.SetDefault("recon.web.enabled", true)

	viper.SetDefault("tools.sqlmap.enabled", true)
	viper.SetDefault("tools.enum4linux_ng.enabled", true)
	viper.SetDefault("tools.nikto.enabled", true)
	viper.SetDefault("tools.dirsearch.enabled", true)
	viper.SetDefault("tools.feroxbuster.enabled", true)
	viper.SetDefault("tools.gobuster.enabled", true)
	viper.SetDefault("tools.dalfox.enabled", true)
	viper.SetDefault("tools.paramspider.enabled", true)
	viper.SetDefault("tools.subzy.enabled", true)
	viper.SetDefault("tools.arjun.enabled", true)
	viper.SetDefault("tools.owasp.enabled", true)
	viper.SetDefault("tools.wafw00f.enabled", true)
	viper.SetDefault("tools.assetfinder.enabled", true)
	viper.SetDefault("tools.bbot.enabled", true)
	viper.SetDefault("tools.subfinder.enabled", true)
	viper.SetDefault("tools.httpx.enabled", true)
	viper.SetDefault("tools.katana.enabled", true)
	viper.SetDefault("tools.nuclei.enabled", true)
	viper.SetDefault("tools.sublist3r.enabled", true)
	viper.SetDefault("tools.amass.enabled", true)
	viper.SetDefault("tools.ffuf.enabled", true)
	viper.SetDefault("tools.trufflehog.enabled", true)

	viper.SetDefault("recon.nuclei.enabled", true)
	viper.SetDefault("recon.bbot.enabled", true)
	viper.SetDefault("recon.subfinder.enabled", true)
	viper.SetDefault("recon.amass.enabled", true)
	viper.SetDefault("recon.sublist3r.enabled", true)
	viper.SetDefault("recon.assetfinder.enabled", true)
	viper.SetDefault("recon.chaos.enabled", true)
	viper.SetDefault("recon.certspotter.enabled", true)
	viper.SetDefault("recon.shuffledns.enabled", true)
	viper.SetDefault("recon.crt.enabled", true)
	viper.SetDefault("recon.crt_db.enabled", true)
	viper.SetDefault("recon.httpx.enabled", true)
	viper.SetDefault("recon.katana.enabled", true)
	viper.SetDefault("recon.gau.enabled", true)
	viper.SetDefault("recon.kiterunner.enabled", true)
	viper.SetDefault("recon.wafw00f.enabled", true)
	viper.SetDefault("recon.cve_search.enabled", true)
	viper.SetDefault("recon.dirsearch.enabled", true)
	viper.SetDefault("recon.feroxbuster.enabled", true)
	viper.SetDefault("recon.gobuster.enabled", true)
	viper.SetDefault("recon.dnsx.enabled", true)
	viper.SetDefault("recon.naabu.enabled", true)

	if len(configPaths) > 0 {
		for _, p := range configPaths {
			viper.AddConfigPath(p)
		}
	} else {
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.config/redrecon")
		viper.AddConfigPath("/etc/redrecon/")
	}
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

	// FIX: Inicializa Cfg antes de unmarshal para garantir que a estrutura seja alocada.
	Cfg = &Config{}
	err := viper.Unmarshal(Cfg)
	if err != nil {
		return err
	}

	// Ensure Recon.Presets is initialized if not present in config
	if Cfg.Recon.Presets == nil {
		Cfg.Recon.Presets = make(map[string]ReconPresetConfig)
	}
	return nil
}

func UpdateToolPathsInConfig() {
	LoadConfig()

	toolsToCheck := []string{
		"subfinder", "httpx", "katana", "nuclei", "nikto", "ffuf",
		"bbot", "dirsearch", "naabu", "sublist3r", "amass", "wafw00f",
		"dalfox", "assetfinder", "feroxbuster", "paramspider", "dnsx", "jsbeautifier-go", "attackmate", "sliver", "sqlmap", "cvesearch", "enum4linuxng",
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
		case "sqlmap": Cfg.ToolPaths.Sqlmap = absPath
		case "cvesearch": Cfg.ToolPaths.CVESearch = absPath
		case "enum4linuxng": Cfg.ToolPaths.Enum4linuxng = absPath
		}
		// Adiciona os novos caminhos para AttackMate e Sliver
		if tool == "attackmate" { Cfg.ToolPaths.Attackmate = absPath }
		if tool == "sliver" { Cfg.ToolPaths.Sliver = absPath }

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

// LoadPresetsFromDir carrega presets de um diretório especificado.
func LoadPresetsFromDir(dir string) error {
	if dir == "" {
		slog.Debug("Diretório de presets não especificado, pulando carregamento de presets.")
		return nil
	}

	// Garante que o mapa de presets esteja inicializado
	if Cfg.Recon.Presets == nil {
		Cfg.Recon.Presets = make(map[string]ReconPresetConfig)
	}

	files, err := os.ReadDir(dir)
	if err != nil {
		slog.Warn("Não foi possível ler o diretório de presets, pode não existir ou estar vazio.", "diretorio", dir, "erro", err)
		return nil // Não é um erro crítico se o diretório não existir ou estiver vazio
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.HasSuffix(file.Name(), ".yaml") && !strings.HasSuffix(file.Name(), ".yml") {
			continue
		}

		filePath := filepath.Join(dir, file.Name())
		content, err := os.ReadFile(filePath)
		if err != nil {
			slog.Error("Erro ao ler arquivo de preset", "arquivo", filePath, "erro", err)
			continue
		}

		var preset ReconPresetConfig
		if err := yaml.Unmarshal(content, &preset); err != nil {
			slog.Error("Erro ao fazer unmarshal do preset", "arquivo", filePath, "erro", err)
			continue
		}

		presetName := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
		Cfg.Recon.Presets[presetName] = preset
		slog.Debug("Preset carregado com sucesso", "nome", presetName, "arquivo", filePath)
	}
	return nil
}
