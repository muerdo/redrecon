
package types

// Finding represents a single discovery of a pattern (e.g., a secret or endpoint).
type Finding struct {
	Pattern string         `json:"pattern"`
	Matches map[string]int `json:"matches"` // Match -> Count
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

// FaviconResult stores the result of a favicon hash analysis.
type FaviconResult struct {
	Host         string `json:"host"`
	FaviconURL   string `json:"favicon_url"`
	Murmur3Hash  string `json:"murmur3_hash"`
	ShodanSearch string `json:"shodan_search"`
}

// NucleiFinding define a estrutura de uma descoberta do Nuclei para parsing do JSON.
type NucleiFinding struct {
	TemplateID  string `json:"template-id"`
	Host        string `json:"host"`
	MatcherName string `json:"matcher-name"`
	Type        string `json:"type"`
	Info        struct {
		Name        string   `json:"name"`
		Severity    string   `json:"severity"`
		Description string   `json:"description"`
		Tags        []string `json:"tags"`
	} `json:"info"`
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
// Adicione esta estrutura ao seu arquivo pkg/types/types.go

// BBotFinding representa um único achado do BBot em formato JSON.
// Apenas os campos relevantes para a extração de subdomínios são mapeados.
type BBotFinding struct {
	Type string `json:"type"`
	Data string `json:"data"`
}