package types

// HttpxTechInfo armazena as informações de tecnologia detectadas pelo httpx.
type HttpxTechInfo struct {
	URL  string   `json:"url"`
	Tech []string `json:"tech"`
}

// CVEResult armazena os detalhes de uma vulnerabilidade CVE encontrada.
type CVEResult struct {
	URL         string `json:"url"`
	Technology  string `json:"technology"`
	CVE_ID      string `json:"cve_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVSS_V3     string `json:"cvss_v3"`
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