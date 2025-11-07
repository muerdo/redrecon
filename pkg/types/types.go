
package types

// Finding represents a single discovery of a pattern (e.g., a secret or endpoint).
type Finding struct {
	Tool     string         `json:"tool"`     // Nome da ferramenta que gerou o achado
	Target   string         `json:"target"`   // Alvo relacionado ao achado
	Evidence string         `json:"evidence"` // Evidência ou descrição detalhada do achado
	Severity string         `json:"severity"` // Severidade do achado (ex: "high", "medium", "low")
	Pattern  string         `json:"pattern"`  // Padrão que foi encontrado (se aplicável)
	Matches  map[string]int `json:"matches"`  // Match -> Count (se aplicável, para padrões)
}

// URLFindings aggregates all findings for a specific URL.
type URLFindings struct {
	URL        string    `json:"url"`
	SourceType string    `json:"source_type,omitempty"` // e.g., "JS", "HTML", "SOURCEMAP"
	Secrets    []Finding `json:"secrets"`
	Endpoints  []Finding `json:"endpoints"`
}

// CVEResult stores the details of a CVE vulnerability found.
type CVEResult struct {
	URL         string `json:"url"`
	Technology  string `json:"technology"`
	CVE_ID      string `json:"cve_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVSS_V3     string `json:"cvss_v3"`
}

// HttpxTechInfo stores technology information detected by httpx.
type HttpxTechInfo struct {
	URL  string   `json:"url"`
	Tech []string `json:"tech"`
}

type NucleiInfo struct {
	Name      string `json:"name"`
	Author    string `json:"author"`
	Severity  string `json:"severity"`
	Description string `json:"description"` // Adicionado para compatibilidade
	Reference []string `json:"reference"`
	Tags      []string `json:"tags"`
}

type NucleiRawOutput struct {
	TemplateID string      `json:"template-id"`
	TemplatePath string    `json:"template-path"`
	Info       NucleiInfo  `json:"info"`
	Type       string      `json:"type"`
	Host       string      `json:"host"`
	MatchedAt  string      `json:"matched-at"`
	Request    string      `json:"request"`
	Response   string      `json:"response"`
}

type NucleiFinding struct {
	ID        string        `json:"id"`  // Único, via template-id + host
	Tool      string        `json:"tool"` // "nuclei"
	Target    string        `json:"target"`
	Severity  string        `json:"severity"`
	Evidence  string        `json:"evidence"`  // Snippet de response
	Timestamp string        `json:"timestamp"`
	Meta      NucleiRawOutput `json:"meta"`
}
// WebhookPayload é a estrutura principal para um payload de webhook do Discord.
type WebhookPayload struct {
	Username string         `json:"username"`
	Embeds   []WebhookEmbed `json:"embeds"`
}

// WebhookEmbed representa um único embed dentro de um payload de webhook.
type WebhookEmbed struct {
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Color       int          `json:"color"`
	Fields      []EmbedField `json:"fields"`
	Footer      *EmbedFooter `json:"footer,omitempty"`
}

// EmbedField representa um campo dentro de um embed do Discord.
type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

// EmbedFooter representa o rodapé de um embed do Discord.
type EmbedFooter struct {
	Text string `json:"text"`
}

type BBotFinding struct {
	Type     string `json:"type"`
	Host     string `json:"host"`
	URL      string `json:"url,omitempty"`
	Severity string `json:"severity,omitempty"`
	Data     any    `json:"data,omitempty"`
}
type WAFResult struct {
	Host string `json:"host"`
	WAF  string `json:"waf"`
}
type SecretFinding struct {
	ID        string `json:"id"`  // Único, via type + file + line
	Tool      string `json:"tool"` // "trufflehog"
	File      string `json:"file"`
	Line      int    `json:"line"`
	Type      string `json:"type"` // ex.: "aws_key"
	Secret    string `json:"secret"`
	Severity  string `json:"severity"` // "high", "medium"
	Evidence  string `json:"evidence"` // Snippet do arquivo
	Entropy   float64 `json:"entropy"`
	Meta      any    `json:"meta"`
}