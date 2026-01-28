package config

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v2"
)

type Config struct {
	APIKeys       APIKeys             `yaml:"apikeys"`    // Chaves de API para diversos serviços.
	Engine        EngineConfig        `yaml:"engine"`     // Já estava correto.
	Recon         ReconConfig         `yaml:"recon"`      // Já estava correto.
	Wordlists     WordlistsConfig     `yaml:"wordlists"`  // Já estava correto.
	Monitor       MonitorConfig       `yaml:"monitor"`    // Já estava correto.
	AI            AIConfig            `yaml:"ai"`         // Já estava correto.
	Evasion       EvasionConfig       `yaml:"evasion"`    // Já estava correto.
	ToolPaths     ToolPathsConfig     `yaml:"tool_paths"` // Já estava correto.
	Metasploit    MetasploitConfig    `yaml:"metasploit"`
	Orchestration OrchestrationConfig `yaml:"orchestration"`
	Tools         ToolsConfig         `yaml:"tools" mapstructure:"tools"`
	Presets       PresetsConfig       `yaml:"presets"`
	Infra         InfraConfig         `yaml:"infra"`
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
	Gemini         string `yaml:"gemini"`     // Chave para Google Gemini
	OpenAI         string `yaml:"openai"`     // Chave para OpenAI
	DeepSeek       string `yaml:"deepseek"`   // Chave para DeepSeek
	GenericAI      string `yaml:"generic_ai"` // Chave genérica para outro provedor de IA
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

type ToolsConfig struct {
	Nmap           string                   `yaml:"nmap"`
	Sqlmap         SqlmapToolConfig         `yaml:"sqlmap"`
	Enum4linuxNG   Enum4linuxNGToolConfig   `yaml:"enum4linux_ng"`
	Nikto          NiktoToolConfig          `yaml:"nikto"`
	Dirsearch      DirsearchToolConfig      `yaml:"dirsearch"`
	Feroxbuster    FeroxbusterToolConfig    `yaml:"feroxbuster"`
	Gobuster       GobusterToolConfig       `yaml:"gobuster"`
	BloodHound     BloodHoundToolConfig     `yaml:"bloodhound"`
	Certipy        CertipyToolConfig        `yaml:"certipy"`
	Impacket       ImpacketToolConfig       `yaml:"impacket"`
	Exchange       ExchangeToolConfig       `yaml:"exchange"` // Novo
	MSSQL          MSSQLToolConfig          `yaml:"mssql"`    // Novo
	BloodyAD       BloodyADToolConfig       `yaml:"bloodyad"` // Novo
	IIS            IISToolConfig            `yaml:"iis"`      // Novo
	CrackMapExec   CrackMapExecToolConfig   `yaml:"crackmapexec"`
	Dalfox         DalfoxToolConfig         `yaml:"dalfox"`
	ParamSpider    ParamSpiderToolConfig    `yaml:"paramspider"`
	Subzy          SubzyToolConfig          `yaml:"subzy"`
	Arjun          ArjunToolConfig          `yaml:"arjun"`
	OWASP          OWASPToolConfig          `yaml:"owasp"`
	Wafw00f        Wafw00fToolConfig        `yaml:"wafw00f"`
	Assetfinder    AssetfinderToolConfig    `yaml:"assetfinder"`
	Bbot           BBotToolConfig           `yaml:"bbot"`
	Subfinder      SubfinderToolConfig      `yaml:"subfinder"`
	Httpx          HttpxToolConfig          `yaml:"httpx"`
	Katana         KatanaToolConfig         `yaml:"katana"`
	Nuclei         NucleiConfig             `yaml:"nuclei" mapstructure:"nuclei"` // Unificado para a struct mais completa
	Sublist3r      Sublist3rToolConfig      `yaml:"sublist3r"`
	Amass          AmassToolConfig          `yaml:"amass"`
	Ffuf           FfufToolConfig           `yaml:"ffuf"`
	TruffleHog     TruffleHogConfig         `yaml:"trufflehog"`
	Naabu          NaabuToolConfig          `yaml:"naabu"`     // Movido de ReconConfig para ToolsConfig
	CVESearch      CVESearchToolConfig      `yaml:"cvesearch"` // Movido de ReconConfig para ToolsConfig
	RustScan       RustScanToolConfig       `yaml:"rustscan"`
	Uncover        UncoverConfig            `yaml:"uncover"`
	Ldapdomaindump LdapdomaindumpToolConfig `yaml:"ldapdomaindump"` // Novo
}

type MetasploitConfig struct {
	Enabled              bool                `yaml:"enabled"`
	Host                 string              `yaml:"host"` // Ex: http://127.0.0.1:55553/api/
	User                 string              `yaml:"user"`
	LHost                string              `yaml:"lhost"`
	LPort                string              `yaml:"lport"`
	Pass                 string              `yaml:"pass"`
	Timeout              string              `yaml:"timeout"` // Ex: "2m"
	Retry                int                 `yaml:"retry"`
	AutoEscalate         bool                `yaml:"auto_escalate"`
	Modules              map[string][]string `yaml:"modules"`               // tech -> []module
	VulnerabilityModules map[string][]string `yaml:"vulnerability_modules"` // vulnerability_type -> []module
}

type OrchestrationConfig struct {
	AttackMate AttackMateConfig `yaml:"attackmate"`
	Sliver     SliverConfig     `yaml:"sliver"`
}

type InfraConfig struct {
	NmapArgs []string `yaml:"nmap-args"`
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

type CrackMapExecToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Protocol  string   `yaml:"protocol"` // smb, winrm, rdp, etc.
	Username  string   `yaml:"username,omitempty"`
	Password  string   `yaml:"password,omitempty"`
	Hash      string   `yaml:"hash,omitempty"`
	Domain    string   `yaml:"domain,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type BloodHoundToolConfig struct {
	Enabled          bool     `yaml:"enabled"`
	CollectionMethod string   `yaml:"collection_method"` // Default, All, DCOnly, etc.
	Domain           string   `yaml:"domain,omitempty"`
	Username         string   `yaml:"username,omitempty"`
	Password         string   `yaml:"password,omitempty"`
	ExtraArgs        []string `yaml:"extra_args,omitempty"`
}

type CertipyToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type ImpacketToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

// ExchangeToolConfig para ataques específicos ao Exchange
type ExchangeToolConfig struct {
	Enabled            bool     `yaml:"enabled"`
	AbuseImpersonation bool     `yaml:"abuse_impersonation"` // Tenta abusar de ApplicationImpersonation
	PillageMailboxes   bool     `yaml:"pillage_mailboxes"`   // Tenta baixar caixas de correio
	ExtraArgs          []string `yaml:"extra_args,omitempty"`
}

// MSSQLToolConfig para ataques a SQL Server
type MSSQLToolConfig struct {
	Enabled          bool     `yaml:"enabled"`
	EnableXPCmdShell bool     `yaml:"enable_xp_cmdshell"` // Tenta habilitar e usar xp_cmdshell
	ExtraArgs        []string `yaml:"extra_args,omitempty"`
}

// IISToolConfig para ataques a IIS
type LdapdomaindumpToolConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type IISToolConfig struct {
	Enabled            bool     `yaml:"enabled"`
	PillageMachineKeys bool     `yaml:"pillage_machine_keys"` // Tenta encontrar e usar machine keys
	ExtraArgs          []string `yaml:"extra_args,omitempty"`
}

// BloodyADToolConfig para ataques com bloodyAD
type BloodyADToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type SubfinderToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	All       bool     `yaml:"all,omitempty"`
	Threads   int      `yaml:"threads,omitempty"`
	Proxy     string   `yaml:"proxy,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type SqlmapToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Proxy     string   `yaml:"proxy,omitempty"`
	Level     int      `yaml:"level,omitempty"` // 1-5
	Risk      int      `yaml:"risk,omitempty"`  // 1-3
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type TruffleHogConfig struct {
	Enabled     bool     `yaml:"enabled"`         // Liga/desliga
	Path        string   `yaml:"path,omitempty"`  // Diretório de arquivos a escanear (herda de resultsPath se vazio)
	Entropy     bool     `yaml:"entropy"`         // Ativa detecção por entropia
	Rules       string   `yaml:"rules,omitempty"` // Path para custom rules (--rules)
	NoVerify    bool     `yaml:"no_verify"`       // Pula verificação de secrets
	Proxy       string   `yaml:"proxy"`           // Proxy para verificações HTTP
	RateLimit   int      `yaml:"rate_limit"`      // 0 = herda de WAF
	Concurrency int      `yaml:"concurrency"`     // 0 = herda de engine.max_parallel_tasks
	JSONOutput  bool     `yaml:"json_output"`     // Força JSON para parsing
	ExtraArgs   []string `yaml:"extra_args"`      // Flags customizadas (ex.: "--only-verified")
}

type ProxyConfig struct {
	Enabled bool   `yaml:"enabled"`
	Address string `yaml:"address"` // Ex: "http://127.0.0.1:8080" ou "socks5://127.0.0.1:9050"
}

type EngineConfig struct {
	MaxParallelTasks int            `yaml:"max_parallel_tasks"`
	Discord          DiscordConfig  `yaml:"discord"`
	WAF              WAFConfig      `yaml:"waf"`
	TempDir          string         `yaml:"temp_dir"`
	Proxy            string         `yaml:"proxy"`
	ResourceLimits   ResourceLimits `yaml:"resource_limits"`
}

type ResourceLimits struct {
	Enabled       bool    `yaml:"enabled"`
	CPUThreshold  float64 `yaml:"cpu_threshold"`  // Percentage (0-100)
	RAMThreshold  float64 `yaml:"ram_threshold"`  // Percentage (0-100)
	CheckInterval string  `yaml:"check_interval"` // e.g., "5s"
}

type AIConfig struct {
	Enabled     bool    `yaml:"enabled"`
	Provider    string  `yaml:"provider"`
	Model       string  `yaml:"model"`
	Temperature float64 `yaml:"temperature"`
	BaseURL     string  `yaml:"base_url"`
}

type WordlistsConfig struct {
	Subdomains string `yaml:"subdomains"`
	Discovery  string `yaml:"discovery"` // Directory/File discovery wordlist
	Fuzzing    string `yaml:"fuzzing"`
	XSS        string `yaml:"xss"`
	SQLi       string `yaml:"sqli"`
	IDOR       string `yaml:"idor"`
	Combined   string `yaml:"combined"` // Combined payload list for active checks
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
	Bloodhoundpy string `yaml:"bloodhoundpy"` // Coletor do BloodHound
	Certipy      string `yaml:"certipy"`
	Impacket     string `yaml:"impacket"` // Diretório para scripts Impacket
	BloodyAD     string `yaml:"bloodyad"`
	Cloudenum    string `yaml:"cloudenum"`
	Sslscan      string `yaml:"sslscan"`
	Sqlmap       string `yaml:"sqlmap"`
	CVESearch    string `yaml:"cvesearch"`
	Enum4linuxng string `yaml:"enum4linuxng"`
	Attackmate   string `yaml:"attackmate"`
	Sliver       string `yaml:"sliver"`
	RustScan     string `yaml:"rustscan"`
}
type DnsxToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	InfraArgs []string `yaml:"infra_args"`
	ExtraArgs []string `yaml:"extra_args"`
}

type MonitorConfig struct {
	Enabled        bool       `yaml:"enabled"`
	Frequency      string     `yaml:"frequency"`        // Frequência padrão (ex: "6h")
	BbotRotation   [][]string `yaml:"bbot_rotation"`    // Lista de grupos de módulos do bbot para alternar
	NucleiLFRGroup string     `yaml:"nuclei_lfr_group"` // Nome do grupo de templates do Nuclei para "low-hanging fruits"
	NotifyOnNew    bool       `yaml:"notify_on_new"`    // Enviar notificação no Discord para novos achados
}

type WebConfig struct {
	Enabled     bool     `yaml:"enabled"`     // Liga/desliga
	Depth       int      `yaml:"depth"`       // Max depth para crawl
	Concurrency int      `yaml:"concurrency"` // Goroutines para análise (0 = MaxParallelTasks)
	Proxy       string   `yaml:"proxy"`       // Proxy para crawl
	ExtraArgs   []string `yaml:"extra_args"`  // Para crawler custom
}
type ReconPresetConfig struct {
	BBot *BBotToolConfig `yaml:"bbot"`
}

type ReconConfig struct {
	EnabledSteps []string                     `yaml:"enabled_steps"` // Define quais ferramentas usar no recon
	Chaos        ChaosToolConfig              `yaml:"chaos"`
	Certspotter  CertspotterToolConfig        `yaml:"certspotter"`
	Shuffledns   ShufflednsToolConfig         `yaml:"shuffledns"`
	Crt          CrtToolConfig                `yaml:"crt"`
	CrtDb        CrtDbToolConfig              `yaml:"crt_db"`
	Gau          GauToolConfig                `yaml:"gau"`
	Kiterunner   KiterunnerToolConfig         `yaml:"kiterunner"`
	Dnsx         DnsxToolConfig               `yaml:"dnsx"`
	Web          WebConfig                    `yaml:"web"`
	Presets      map[string]ReconPresetConfig `yaml:"presets"`
}

type NucleiConfig struct {
	Enabled          bool                `yaml:"enabled"`                                            // Adicionado para controlar a ativação da ferramenta.
	Templates        []string            `yaml:"templates" mapstructure:"templates"`                 // Diretórios/arquivos de templates (ex.: "cves/", "technologies/")
	OWASPTemplates   []string            `yaml:"owasp_templates" mapstructure:"owasp_templates"`     // Templates OWASP específicos
	MonitorTemplates []string            `yaml:"monitor_templates" mapstructure:"monitor_templates"` // Para monitoramento contínuo
	Proxy            string              `yaml:"proxy"`                                              // Proxy para evasão (herda de WAF se vazio)
	RateLimit        int                 `yaml:"rate_limit"`                                         // 0 = herda de WAF
	Concurrency      int                 `yaml:"concurrency"`                                        // 0 = herda de engine.max_parallel_tasks
	TemplatesGroups  map[string][]string `yaml:"templates_groups"`                                   // Grupos de templates pré-definidos (ex: light, full)
	Aggressive       bool                `yaml:"aggressive"`                                         // Ativa templates mais invasivos
	Headless         bool                `yaml:"headless"`                                           // Modo sem interatividade
	JSONOutput       bool                `yaml:"json_output"`                                        // Força output JSON para parsing
	UpdateTemplates  bool                `yaml:"update_templates"`                                   // Adicionado para corresponder ao uso
	ExtraArgs        []string            `yaml:"extra_args"`                                         // Flags customizadas (ex.: "-severity critical")
	InteractshURL    string              `yaml:"interactsh_url,omitempty"`
	InteractshToken  string              `yaml:"interactsh_token,omitempty"`
	Silent           bool                `yaml:"silent,omitempty"`
	Timeout          int                 `yaml:"timeout,omitempty"`
	OutputDir        string              `yaml:"output_dir,omitempty"`
}

type BBotToolConfig struct {
	Enabled         bool                `yaml:"enabled"`        // liga/desliga o BBOT
	Presets         []string            `yaml:"presets"`        // -p preset1 preset2
	Flags           []string            `yaml:"flags"`          // -f subdomain-enum,web-basic
	Modules         []string            `yaml:"modules"`        // módulos individuais
	OutputModules   []string            `yaml:"output_modules"` // txt, json, neo4j, etc.
	Include         []string            `yaml:"include,omitempty"`
	ExcludeModules  []string            `yaml:"exclude_modules,omitempty"`
	Blacklist       []string            `yaml:"blacklist,omitempty"`
	RateLimit       int                 `yaml:"rate_limit"`       // 0 = usa perfil WAF
	Concurrency     int                 `yaml:"concurrency"`      // 0 = usa engine.max_parallel_tasks
	Proxy           string              `yaml:"proxy"`            // vazio = usa perfil WAF
	AllowDeadly     bool                `yaml:"allow_deadly"`     // --allow-deadly
	ExtraArgs       []string            `yaml:"extra_args"`       // qualquer flag desconhecida
	ModulesGroups   map[string][]string `yaml:"modules_groups"`   // Grupos de módulos pré-definidos (ex: light, full)
	ConfigOverrides map[string]any      `yaml:"config_overrides"` // sobrescreve bbot.yml interno
	ListModules     bool                `yaml:"list_modules"`     // Se true, lista os módulos do BBOT no início
}

// Default BBOT modules (extracted from https://www.blacklanternsecurity.com/bbot/Stable/modules/list_of_modules/)
var DefaultBBotModules = []string{
	"ajaxpro", "aspnet_bin_exposure", "baddns", "bucket_amazon", "dnsbrute", "ffuf", "git", "httpx", "nuclei", "portscan", "retirejs", "wafw00f", "wpscan",
	"anubisdb", "asn", "builtwith", "chaos", "crt", "dehashed", "fullhunt", "github_codesearch", "hunterio", "shodan_dns", "wayback",
	"asset_inventory", "csv", "discord", "json", "nmap_xml", "slack", "stdout", "web_report",
	"cloudcheck", "dnsresolve", "aggregate", "speculate",
}

type Enum4linuxNGToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Domain    string   `yaml:"domain,omitempty"`
	Username  string   `yaml:"username,omitempty"`
	Password  string   `yaml:"password,omitempty"`
	Threads   int      `yaml:"threads,omitempty"`
	RateLimit int      `yaml:"rate_limit,omitempty"`
	Flags     []string `yaml:"flags,omitempty"`
	Proxy     string   `yaml:"proxy,omitempty"`
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
	Enabled         bool     `yaml:"enabled"`
	RateLimit       int      `yaml:"rate_limit"` // 0 significa usar o rate_limit do perfil WAF, caso contrário, sobrescreve
	Proxy           string   `yaml:"proxy"`      // Vazio significa usar o proxy do perfil WAF, caso contrário, sobrescreve
	ExtraArgs       []string `yaml:"extra_args,omitempty"`
	InteractshURL   string   `yaml:"interactsh_url,omitempty"`
	InteractshToken string   `yaml:"interactsh_token,omitempty"`
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

type HttpxToolConfig struct {
	Enabled         bool     `yaml:"enabled"`
	FollowRedirects bool     `yaml:"follow_redirects,omitempty"`
	Threads         int      `yaml:"threads,omitempty"`
	Proxy           string   `yaml:"proxy,omitempty"`
	VulnTemplates   []string `yaml:"vuln_templates,omitempty"`
	ExtraArgs       []string `yaml:"extra_args,omitempty"`
}

type DirsearchToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Threads   int      `yaml:"threads,omitempty"`
	Proxy     string   `yaml:"proxy,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type FeroxbusterToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Threads   int      `yaml:"threads,omitempty"`
	Proxy     string   `yaml:"proxy,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}
type WAFProfile struct {
	RateLimit   int      `yaml:"rate_limit"`
	Concurrency int      `yaml:"concurrency"`
	ProxyFile   string   `yaml:"proxy_file"`
	Proxy       string   `yaml:"proxy,omitempty"`
	Proxies     []string `yaml:"default_proxies,omitempty"`
}
type NiktoToolConfig struct {
	Enabled         bool     `yaml:"enabled"`
	OutputFile      string   `yaml:"output_file,omitempty"`
	OutputFormat    string   `yaml:"output_format,omitempty"`
	Tuning          string   `yaml:"tuning,omitempty"`
	PauseSeconds    float64  `yaml:"pause_seconds,omitempty"`
	Proxy           string   `yaml:"proxy,omitempty"`
	MaxTime         int      `yaml:"maxtime,omitempty"` // Em segundos
	Evasion         string   `yaml:"evasion,omitempty"` // Ex: "1"
	Mutate          string   `yaml:"mutate,omitempty"`  // Ex: "1,2,3"
	FollowRedirects bool     `yaml:"follow_redirects"`
	Timeout         int      `yaml:"timeout,omitempty"` // Em segundos
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
	Enabled         bool     `yaml:"enabled"`
	Threads         int      `yaml:"threads,omitempty"`
	Proxy           string   `yaml:"proxy,omitempty"`
	ExtraArgs       []string `yaml:"extra_args,omitempty"`
	InteractshURL   string   `yaml:"interactsh_url,omitempty"`
	InteractshToken string   `yaml:"interactsh_token,omitempty"`
}

type DalfoxToolConfig struct {
	Enabled         bool     `yaml:"enabled"`
	Proxy           string   `yaml:"proxy,omitempty"`
	ExtraArgs       []string `yaml:"extra_args,omitempty"`
	InteractshURL   string   `yaml:"interactsh_url,omitempty"`
	InteractshToken string   `yaml:"interactsh_token,omitempty"`
}

type ParamSpiderToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Proxy     string   `yaml:"proxy,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type SubzyToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type ArjunToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
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

type RustScanToolConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Path      string   `yaml:"path,omitempty"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type UncoverConfig struct {
	Enabled   bool     `yaml:"enabled"`
	Engines   []string `yaml:"engines"`
	Limit     int      `yaml:"limit"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

// A declaração duplicada de Enum4linuxNGToolConfig foi removida.
type WAFConfig struct {
	Enabled        bool                  `yaml:"enabled"`
	DefaultProfile string                `yaml:"default_profile"` // ← STRING
	Profiles       map[string]WAFProfile `yaml:"profiles"`
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

	if len(profile.Proxies) > 0 {
		slog.Debug("Creating temporary proxy file from default proxy list.")
		proxyFile, err := os.CreateTemp(tempDir, "default-proxies-*.txt")
		if err != nil {
			slog.Error("Failed to create temporary default proxy file", "error", err)
			return "", false
		}
		defer proxyFile.Close()

		_, err = proxyFile.WriteString(strings.Join(profile.Proxies, "\n"))
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
	// Verifica se a etapa está habilitada na lista `enabled_steps` do recon.
	for _, enabledStep := range c.EnabledSteps {
		if enabledStep == tool {
			return true
		}
	}
	return false
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
	case "bloodhound.py":
		customPath = Cfg.ToolPaths.Bloodhoundpy
	case "certipy":
		customPath = Cfg.ToolPaths.Certipy
	case "bloodyAD":
		customPath = Cfg.ToolPaths.BloodyAD
	case "impacket-getuserspns": // Exemplo para um script impacket
		return filepath.Join(Cfg.ToolPaths.Impacket, "GetUserSPNs.py")
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
	case "rustscan":
		customPath = Cfg.ToolPaths.RustScan
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
		"assetfinder", "feroxbuster", "paramspider", "dnsx", "naabu", "bloodhound.py", "bloodyAD",
		"certipy", "impacket-getuserspns", "crackmapexec", "svmap", "cloudenum", "sslscan", "sqlmap",
		"cvesearch", "enum4linuxng", "attackmate", "sliver", "subzy", "rustscan",
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

	return unmarshalConfig()
}

// LoadConfig procura e carrega a configuração de caminhos padrão ou de um arquivo/caminho específico.
func LoadConfig(configPaths ...string) error {
	// Reset Viper para garantir que não haja configurações residuais de chamadas anteriores
	viper.Reset()

	viper.SetDefault("engine.max_parallel_tasks", 5)
	viper.SetDefault("tools.nmap", "/usr/bin/nmap")
	viper.SetDefault("tools.sqlmap", "/usr/bin/sqlmap")

	// Set default for BBOT modules and list_modules
	viper.SetDefault("recon.bbot.list_modules", true)
	// Only set DefaultBBotModules if it's not already configured.
	// This prevents overwriting user-defined modules if they exist in a loaded config.
	// However, viper.SetDefault is usually applied before reading the config.
	// So, if the config file has `recon.bbot.modules`, it will override this default.
	// The current logic in `LoadConfig` is to set defaults, then read config, then unmarshal.
	// This means `DefaultBBotModules` will be the default if nothing is specified in the file.
	// This is fine.
	// The issue is that `DefaultBBotModules` is a global var, so if it's modified elsewhere,
	// it affects this default. But it's a const-like slice, so it should be fine.
	// Let's ensure it's not nil or empty.
	// If `DefaultBBotModules` is intended to be a *default* value, it should be set here.
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

	// Define quais ferramentas são habilitadas por padrão na fase de 'recon'.
	viper.SetDefault("recon.enabled_steps", []string{
		"subfinder", "amass", "assetfinder", "bbot", "httpx", "katana", "wafw00f",
		"cve_search", "naabu", "dalfox", "nikto", "nuclei",
	})

	// Habilita todas as ferramentas por padrão dentro da seção 'tools'.
	// A execução real dependerá se a etapa está em `recon.enabled_steps` ou se é chamada por outro comando.
	enableAllToolsByDefault()

	// Filter out empty paths
	var validPaths []string
	for _, p := range configPaths {
		if p != "" {
			validPaths = append(validPaths, p)
		}
	}

	var configLoaded bool
	if len(validPaths) > 0 {
		for _, p := range validPaths {
			fileInfo, err := os.Stat(p)
			if err == nil {
				if fileInfo.IsDir() {
					viper.AddConfigPath(p)
					viper.SetConfigName("config") // Look for 'config.yaml' in this directory
					viper.SetConfigType("yaml")
				} else { // It's a file
					viper.SetConfigFile(p) // Load this specific file
				}
				// Attempt to read the config
				if errRead := viper.ReadInConfig(); errRead == nil {
					configLoaded = true
					break // Stop after the first successful load
				} else {
					slog.Warn("Failed to read config from specified path, trying next...", "path", p, "error", errRead)
				}
			} else {
				slog.Warn("Specified config path does not exist or is inaccessible, trying next...", "path", p, "error", err)
			}
		}
	} else {
		viper.AddConfigPath(".")
		viper.AddConfigPath("$HOME/.config/redrecon")
		viper.AddConfigPath("/etc/redrecon/")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		// Attempt to read from default paths
		if errRead := viper.ReadInConfig(); errRead == nil {
			configLoaded = true
		} else if _, ok := errRead.(viper.ConfigFileNotFoundError); !ok {
			// Found config but failed to read (e.g. invalid YAML)
			slog.Warn("Found config file but failed to read it", "error", errRead)
		}
	}

	if !configLoaded {
		slog.Warn("No configuration file found. Using default values.")
	}

	return unmarshalConfig()
}

// SaveConfig writes the current configuration back to the file
func SaveConfig() error {
	filename := viper.ConfigFileUsed()
	if filename == "" {
		// If no config file was loaded, define a default path
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		filename = filepath.Join(home, ".config", "redrecon", "config.yaml")
	}

	// Ensure directory exists
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return viper.WriteConfigAs(filename)
}

func enableAllToolsByDefault() {
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
	viper.SetDefault("tools.bloodhound.enabled", true)
	viper.SetDefault("tools.certipy.enabled", true)
	viper.SetDefault("tools.bloodyad.enabled", true)
	viper.SetDefault("tools.impacket.enabled", true)
	viper.SetDefault("tools.trufflehog.enabled", true)
	viper.SetDefault("recon.chaos.enabled", true)
	viper.SetDefault("recon.certspotter.enabled", true)
	viper.SetDefault("recon.shuffledns.enabled", true)
	viper.SetDefault("recon.naabu.enabled", true)
	viper.SetDefault("tools.naabu.enabled", true)     // Adicionado para consistência
	viper.SetDefault("tools.cvesearch.enabled", true) // Adicionado para consistência
}

func UpdateToolPathsInConfig() {
	// LoadConfig() // This will reset Viper and potentially lose current config.
	// Instead, just ensure Cfg is loaded if it's nil.
	if Cfg == nil {
		LoadConfig() // Load defaults if not already loaded
	}

	toolsToCheck := []string{
		"subfinder", "httpx", "katana", "nuclei", "nikto", "ffuf",
		"bbot", "dirsearch", "naabu", "sublist3r", "amass", "wafw00f", "bloodyAD",
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
		case "subfinder":
			Cfg.ToolPaths.Subfinder = absPath
		case "httpx":
			Cfg.ToolPaths.Httpx = absPath
		case "katana":
			Cfg.ToolPaths.Katana = absPath
		case "nuclei":
			Cfg.ToolPaths.Nuclei = absPath
		case "nikto":
			Cfg.ToolPaths.Nikto = absPath
		case "ffuf":
			Cfg.ToolPaths.Ffuf = absPath
		case "bbot":
			Cfg.ToolPaths.Bbot = absPath
		case "dirsearch":
			Cfg.ToolPaths.Dirsearch = absPath
		case "sublist3r":
			Cfg.ToolPaths.Sublist3r = absPath
		case "amass":
			Cfg.ToolPaths.Amass = absPath
		case "wafw00f":
			Cfg.ToolPaths.Wafw00f = absPath
		case "dalfox":
			Cfg.ToolPaths.Dalfox = absPath
		case "assetfinder":
			Cfg.ToolPaths.Assetfinder = absPath
		case "feroxbuster":
			Cfg.ToolPaths.Feroxbuster = absPath
		case "paramspider":
			Cfg.ToolPaths.Paramspider = absPath
		case "dnsx":
			Cfg.ToolPaths.Dnsx = absPath
		case "naabu":
			Cfg.ToolPaths.Naabu = absPath
		case "crackmapexec":
			Cfg.ToolPaths.Crackmapexec = absPath
		case "svmap":
			Cfg.ToolPaths.Svmap = absPath
		case "cloudenum":
			Cfg.ToolPaths.Cloudenum = absPath
		case "sslscan":
			Cfg.ToolPaths.Sslscan = absPath
		case "sqlmap":
			Cfg.ToolPaths.Sqlmap = absPath
		case "cvesearch":
			Cfg.ToolPaths.CVESearch = absPath
		case "bloodyAD":
			Cfg.ToolPaths.BloodyAD = absPath
		case "enum4linuxng":
			Cfg.ToolPaths.Enum4linuxng = absPath
		}
		// Adiciona os novos caminhos para AttackMate e Sliver
		if tool == "attackmate" {
			Cfg.ToolPaths.Attackmate = absPath
		}
		if tool == "sliver" {
			Cfg.ToolPaths.Sliver = absPath
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
