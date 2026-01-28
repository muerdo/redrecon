package types

import (
	"fmt"
	"strings"
	"time"
)

// Credentials armazena as credenciais para autenticação.
type Credentials struct {
	Username string
	Password string
	Hash     string // Formato NTLM
	Domain   string
}

// URLFindings armazena segredos e endpoints encontrados em uma URL.
type URLFindings struct {
	URL        string    `json:"url"`
	SourceType string    `json:"source_type"` // "HTML", "JS", "SourceMap"
	Secrets    []Finding `json:"secrets"`
	Endpoints  []Finding `json:"endpoints"`
}

// NucleiFinding representa uma descoberta do Nuclei.
type NucleiFinding struct {
	ID        string
	Tool      string
	Target    string
	Severity  string
	Timestamp string
	Meta      NucleiRawOutput
}

// NucleiRawOutput é a estrutura para o output JSON bruto do Nuclei.
type NucleiRawOutput struct {
	TemplateID string `json:"template-id"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name        string   `json:"name"`
		Author      []string `json:"author"`
		Tags        []string `json:"tags"`
		Description string   `json:"description"`
		Severity    string   `json:"severity"`
	} `json:"info"`
}

// CVEResult representa um resultado de pesquisa de CVE.
type CVEResult struct {
	URL         string `json:"url"`
	Technology  string `json:"technology"`
	CVE_ID      string `json:"cve_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVSS_V3     string `json:"cvss_v3"`
}

// BBotFinding representa uma descoberta do BBot.
type BBotFinding struct {
	Type     string
	Host     string
	URL      string
	Severity string
	Data     interface{}
}

// ADReconStepResult armazena o resultado de uma única etapa do AD recon.
type ADReconStepResult struct {
	Success    bool
	OutputFile string
	Error      string
}

// ADReconSummary resume os resultados do fluxo de trabalho do AD Explorer.
type ADReconSummary struct {
	TaskName string
	Domain   string
	Time     time.Time
	Steps    map[string]ADReconStepResult
}

func (s ADReconSummary) String() string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("--- Resumo do AD Explorer para a Tarefa: %s (Domínio: %s) ---\n", s.TaskName, s.Domain))
	for name, result := range s.Steps {
		status := "✅ SUCESSO"
		if !result.Success {
			status = "❌ FALHA"
		}
		builder.WriteString(fmt.Sprintf("\n[%s] Etapa: %s\n", status, name))
		builder.WriteString(fmt.Sprintf("  - Arquivo de Saída/Info: %s\n", result.OutputFile))
		if result.Error != "" {
			builder.WriteString(fmt.Sprintf("  - Erro: %s\n", result.Error))
		}
	}
	return builder.String()
}

// WAFResult armazena o resultado da detecção de WAF para um host.
type WAFResult struct {
	Host string `json:"host"`
	WAF  string `json:"waf"`
}

// WebhookPayload é o objeto raiz para uma mensagem de webhook do Discord.
type WebhookPayload struct {
	Content   string         `json:"content,omitempty"`
	Username  string         `json:"username,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
	Embeds    []WebhookEmbed `json:"embeds,omitempty"`
}

// WebhookEmbed representa um objeto de incorporação em uma mensagem de webhook do Discord.
type WebhookEmbed struct {
	Title       string       `json:"title,omitempty"`
	Description string       `json:"description,omitempty"`
	URL         string       `json:"url,omitempty"`
	Timestamp   string       `json:"timestamp,omitempty"`
	Color       int          `json:"color,omitempty"`
	Footer      *EmbedFooter `json:"footer,omitempty"`
	Fields      []EmbedField `json:"fields,omitempty"`
}

// EmbedField representa um campo em uma incorporação do Discord.
type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// EmbedFooter representa o rodapé de uma incorporação do Discord.
type EmbedFooter struct {
	Text    string `json:"text"`
	IconURL string `json:"icon_url,omitempty"`
}

// HttpxResult represents a single result from httpx JSON output.
type HttpxResult struct {
	Timestamp     time.Time   `json:"timestamp"`
	ASN           interface{} `json:"asn"` // Can be struct or nil
	CSP           interface{} `json:"csp"`
	TLS           interface{} `json:"tls"`
	Hashes        interface{} `json:"hashes"`
	Header        interface{} `json:"header"`
	URL           string      `json:"url"`
	Input         string      `json:"input"`
	Location      string      `json:"location"`
	Title         string      `json:"title"`
	Scheme        string      `json:"scheme"`
	Webserver     string      `json:"webserver"`
	ContentType   string      `json:"content_type"`
	Method        string      `json:"method"`
	Host          string      `json:"host"`
	Port          string      `json:"port"`
	Path          string      `json:"path"`
	Favicon       string      `json:"favicon"`
	IsCDN         bool        `json:"is_cdn"`
	StatusCode    int         `json:"status_code"`
	ContentLength int         `json:"content_length"`
	Failed        bool        `json:"failed"`
	Tech          []string    `json:"tech"`
}
