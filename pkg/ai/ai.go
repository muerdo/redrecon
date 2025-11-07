package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"redrecon/internal/config"
	"redrecon/pkg/analysis"
	"redrecon/pkg/types"
)

// AIRequest representa o payload enviado para a API da IA.
type AIRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature"`
}

// Message representa uma mensagem no chat (sistema, usuário, assistente).
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// AIResponse representa a resposta recebida da API da IA.
type AIResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// AnalysisResult contém a análise da IA para um conjunto de achados.
type AnalysisResult struct {
	Title       string `json:"title"`
	Summary     string `json:"summary"`
	IsLikelyTruePositive bool `json:"is_likely_true_positive"`
	Severity    string `json:"severity"` // Ex: "Crítica", "Alta", "Média", "Baixa", "Informativa"
	Remediation string `json:"remediation"`
}

// AnalyzeFindingsWithAI envia os achados para um modelo de IA para análise.
func AnalyzeFindingsWithAI(ctx context.Context, findings interface{}, logger *slog.Logger) (*AnalysisResult, error) {
	if !config.Cfg.AI.Enabled {
		return nil, fmt.Errorf("AI analysis is disabled in the configuration")
	}

	prompt, err := buildPromptForFinding(findings)
	if err != nil {
		return nil, err
	}

	logger.Info("Sending findings to AI for analysis...", "provider", config.Cfg.AI.Provider, "model", config.Cfg.AI.Model)

	aiResponse, err := queryAI(ctx, prompt)
	if err != nil {
		return nil, fmt.Errorf("failed to query AI provider: %w", err)
	}

	// Tenta fazer o parse da resposta da IA como JSON.
	var analysisResult AnalysisResult
	if err := json.Unmarshal([]byte(aiResponse), &analysisResult); err != nil {
		logger.Warn("Failed to unmarshal AI response as JSON, using raw text.", "error", err, "raw_response", aiResponse)
		// Fallback: se a IA não retornar um JSON válido, usamos a resposta bruta como sumário.
		return &AnalysisResult{
			Title:   "Análise de IA (Texto Bruto)",
			Summary: aiResponse,
		}, nil
	}

	return &analysisResult, nil
}

// queryAI executa a chamada HTTP para a API da IA.
func queryAI(ctx context.Context, prompt string) (string, error) {
	var apiKey, baseURL string

	// Determina a chave de API e a URL base com base no provedor.
	switch strings.ToLower(config.Cfg.AI.Provider) {
	case "openai":
		apiKey = config.Cfg.AI.OpenAIAPIKey
		baseURL = "https://api.openai.com/v1"
	case "deepseek":
		apiKey = config.Cfg.AI.DeepSeekAPIKey
		baseURL = "https://api.deepseek.com/v1"
	default:
		// Usa a configuração genérica como fallback.
		apiKey = config.Cfg.AI.APIKey
		baseURL = config.Cfg.AI.BaseURL
	}

	if apiKey == "" {
		return "", fmt.Errorf("API key for provider '%s' is not configured", config.Cfg.AI.Provider)
	}

	requestBody, err := json.Marshal(AIRequest{
		Model:       config.Cfg.AI.Model,
		Temperature: config.Cfg.AI.Temperature,
		Messages: []Message{
			{
				Role:    "system",
				Content: getSystemPrompt(),
			},
			{
				Role:    "user",
				Content: prompt,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to marshal AI request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", baseURL+"/chat/completions", bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to create AI request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request to AI API: %w", err)
	}
	defer resp.Body.Close()

	var aiResp AIResponse
	if err := json.NewDecoder(resp.Body).Decode(&aiResp); err != nil {
		return "", fmt.Errorf("failed to decode AI API response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		if aiResp.Error != nil {
			return "", fmt.Errorf("AI API returned error: %s", aiResp.Error.Message)
		}
		return "", fmt.Errorf("AI API returned non-200 status: %d", resp.StatusCode)
	}

	if len(aiResp.Choices) == 0 {
		return "", fmt.Errorf("AI API returned no choices")
	}

	return aiResp.Choices[0].Message.Content, nil
}

// getSystemPrompt define o comportamento da IA.
func getSystemPrompt() string {
	return `Você é um especialista em segurança ofensiva (pentester) de classe mundial. Sua tarefa é analisar os resultados de ferramentas de segurança e fornecer uma avaliação concisa e precisa.
Responda SEMPRE no formato JSON, usando a seguinte estrutura:
{
  "title": "Um título curto para o achado (ex: SQL Injection no Login)",
  "summary": "Um resumo técnico explicando a vulnerabilidade, por que ela é um risco e como foi encontrada.",
  "is_likely_true_positive": true,
  "severity": "Crítica | Alta | Média | Baixa | Informativa",
  "remediation": "Uma sugestão clara e acionável de como corrigir a vulnerabilidade."
}
Se a vulnerabilidade parecer um falso positivo, defina "is_likely_true_positive" como false e explique o motivo no sumário.
Se a entrada for um log de erro, analise o erro, explique a causa provável e sugira uma solução na seção "remediation". O título deve ser "Análise de Erro".`
}

// buildPromptForFinding cria um prompt específico para o tipo de achado.
func buildPromptForFinding(finding interface{}) (string, error) {
	var prompt strings.Builder
	prompt.WriteString("Analise o seguinte achado de segurança:\n\n")

	switch f := finding.(type) {
	case types.NucleiFinding:
		prompt.WriteString(fmt.Sprintf("Ferramenta: Nuclei\n"))
		prompt.WriteString(fmt.Sprintf("Template ID: %s\n", f.Meta.TemplateID))
		prompt.WriteString(fmt.Sprintf("Nome: %s\n", f.Meta.Info.Name))
		prompt.WriteString(fmt.Sprintf("Severidade Reportada: %s\n", f.Meta.Info.Severity))
		prompt.WriteString(fmt.Sprintf("Host Afetado: %s\n", f.Meta.Host))
		prompt.WriteString(fmt.Sprintf("Descrição: %s\n", f.Meta.Info.Description))
	case analysis.NiktoFinding:
		prompt.WriteString(fmt.Sprintf("Ferramenta: Nikto\n"))
		prompt.WriteString(fmt.Sprintf("Host: %s\n", f.Host))
		prompt.WriteString(fmt.Sprintf("Mensagem: %s\n", f.Message))
	case analysis.HttpxVulnerabilityFinding:
		prompt.WriteString(fmt.Sprintf("Ferramenta: Httpx (modo de vulnerabilidade)\n"))
		prompt.WriteString(fmt.Sprintf("URL: %s\n", f.URL))
		prompt.WriteString(fmt.Sprintf("Tipo Inferido: %s\n", f.Type))
	case types.CVEResult:
		prompt.WriteString(fmt.Sprintf("Ferramenta: NVD API Search\n"))
		prompt.WriteString(fmt.Sprintf("CVE ID: %s\n", f.CVE_ID))
		prompt.WriteString(fmt.Sprintf("Tecnologia: %s\n", f.Technology))
		prompt.WriteString(fmt.Sprintf("URL Afetada: %s\n", f.URL))
		prompt.WriteString(fmt.Sprintf("Descrição: %s\n", f.Description))
	case string: // Para análise de erros
		prompt.WriteString("Tipo de Entrada: Log de Erro\n")
		prompt.WriteString(fmt.Sprintf("Log: \n---\n%s\n---", f))
	default:
		return "", fmt.Errorf("unsupported finding type for AI analysis: %T", f)
	}

	prompt.WriteString("\nForneça sua análise no formato JSON especificado.")
	return prompt.String(), nil
}
