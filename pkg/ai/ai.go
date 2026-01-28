package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"redrecon/internal/config"
	"redrecon/pkg/analysis"
	"redrecon/pkg/types"
)

// GeminiRequest representa o payload para a API do Gemini.
type GeminiRequest struct {
	Contents []*GeminiContent `json:"contents"`
}

// GeminiContent representa o conteúdo da mensagem para o Gemini.
type GeminiContent struct {
	Parts []*GeminiPart `json:"parts"`
}

// GeminiPart representa uma parte do conteúdo (texto).
type GeminiPart struct {
	Text string `json:"text"`
}

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

// GeminiResponse representa a resposta da API do Gemini.
type GeminiResponse struct {
	Candidates []struct {
		Content GeminiContent `json:"content"`
	} `json:"candidates"`
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

	aiResponse, err := queryAI(ctx, getSystemPrompt(), prompt)
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
func queryAI(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	var apiKey, url, provider string
	var requestBody []byte
	var err error

	provider = strings.ToLower(config.Cfg.AI.Provider)

	switch provider {
	case "openai":
		apiKey = config.Cfg.APIKeys.OpenAI
		url = "https://api.openai.com/v1/chat/completions"
		// Constrói o corpo da requisição para OpenAI
		requestBody, err = json.Marshal(AIRequest{
			Model:       config.Cfg.AI.Model,
			Temperature: config.Cfg.AI.Temperature,
			Messages: []Message{
				{Role: "system", Content: systemPrompt},
				{Role: "user", Content: userPrompt},
			},
		})
	case "deepseek":
		apiKey = config.Cfg.APIKeys.DeepSeek
		url = "https://api.deepseek.com/v1/chat/completions"
		// Constrói o corpo da requisição para DeepSeek (similar ao OpenAI)
		requestBody, err = json.Marshal(AIRequest{
			Model:       config.Cfg.AI.Model,
			Temperature: config.Cfg.AI.Temperature,
			Messages: []Message{
				{Role: "system", Content: systemPrompt},
				{Role: "user", Content: userPrompt},
			},
		})
	case "gemini":
		apiKey = config.Cfg.APIKeys.Gemini
		// A URL do Gemini não deve conter a chave; ela é passada no cabeçalho.
		url = fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", config.Cfg.AI.Model)
		// Constrói o corpo da requisição para Gemini
		fullPrompt := systemPrompt + "\n\n" + userPrompt
		requestBody, err = json.Marshal(GeminiRequest{
			Contents: []*GeminiContent{
				{Parts: []*GeminiPart{{Text: fullPrompt}}},
			},
		})
	default:
		return "", fmt.Errorf("provedor de IA desconhecido: '%s'", config.Cfg.AI.Provider)
	}

	if err != nil {
		return "", fmt.Errorf("falha ao serializar o corpo da requisição para %s: %w", provider, err)
	}

	if apiKey == "" {
		return "", fmt.Errorf("a chave de API para o provedor '%s' não está configurada", provider)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(requestBody))
	if err != nil {
		return "", fmt.Errorf("failed to create AI request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	// Define o cabeçalho de autorização correto para cada provedor.
	if provider == "openai" || provider == "deepseek" {
		req.Header.Set("Authorization", "Bearer "+apiKey)
	} else if provider == "gemini" {
		req.Header.Set("X-goog-api-key", apiKey)
	}

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request to AI API:. %w", err)
	}
	defer resp.Body.Close()

	// Processa a resposta de acordo com o provedor
	if provider == "gemini" {
		var geminiResp GeminiResponse
		if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
			return "", fmt.Errorf("falha ao decodificar a resposta da API do Gemini: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			if geminiResp.Error != nil {
				return "", fmt.Errorf("a API do Gemini retornou um erro: %s", geminiResp.Error.Message)
			}
			return "", fmt.Errorf("a API do Gemini retornou um status não-200: %d", resp.StatusCode)
		}
		if len(geminiResp.Candidates) > 0 && len(geminiResp.Candidates[0].Content.Parts) > 0 {
			return geminiResp.Candidates[0].Content.Parts[0].Text, nil
		}
		return "", fmt.Errorf("a API do Gemini retornou uma resposta vazia")
	} else { // OpenAI e DeepSeek
		var aiResp AIResponse
		if err := json.NewDecoder(resp.Body).Decode(&aiResp); err != nil {
			return "", fmt.Errorf("falha ao decodificar a resposta da API de IA: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			if aiResp.Error != nil {
				return "", fmt.Errorf("a API de IA retornou um erro: %s", aiResp.Error.Message)
			}
			return "", fmt.Errorf("a API de IA retornou um status não-200: %d", resp.StatusCode)
		}
		if len(aiResp.Choices) > 0 {
			return aiResp.Choices[0].Message.Content, nil
		}
		return "", fmt.Errorf("a API de IA não retornou nenhuma escolha")
	}
}

// getHolisticSystemPrompt define o comportamento da IA para análise holística.
func getHolisticSystemPrompt() string {
	return `Você é um especialista sênior em segurança ofensiva e pentest, com vasta experiência em Red Team e análise de vulnerabilidades. Sua tarefa é realizar uma análise holística e aprofundada dos resultados consolidados de um scan de segurança para um determinado alvo.

**Objetivo:**
Analisar TODOS os dados fornecidos (subdomínios, portas abertas, serviços, tecnologias, vulnerabilidades, etc.) para identificar vetores de ataque, correlacionar informações e construir uma cadeia de exploração (attack chain) realista e criativa. Vá além do óbvio. Pense em como um atacante real combinaria informações aparentemente inofensivas para comprometer o alvo.

**Formato da Resposta (Obrigatório - Use Markdown):**

1.  **## Resumo Executivo**
    *   Uma breve visão geral do estado de segurança do alvo.
    *   Destaque os 2-3 riscos de negócio mais críticos identificados.

2.  **## Superfície de Ataque**
    *   **Subdomínios e Ativos:** Liste os subdomínios mais interessantes e por quê.
    *   **Portas e Serviços:** Liste as portas e serviços expostos mais críticos e o risco associado a cada um.
    *   **Tecnologias Identificadas:** Liste as tecnologias chave (servidores web, frameworks, etc.) e como elas podem ser exploradas.

3.  **## Vetores de Ataque e Cadeia de Exploração (Attack Chain)**
    *   Descreva em detalhes um ou mais cenários de ataque passo a passo.
    *   **Cenário 1: [Nome do Cenário, ex: "Comprometimento via API Exposta"]**
        *   **Passo 1 - Reconhecimento:** Como você usou os dados de subdomínios e portas para encontrar o ponto de entrada.
        *   **Passo 2 - Ponto de Entrada:** Qual vulnerabilidade específica (ex: SSRF, SQLi, RCE) você exploraria.
        *   **Passo 3 - Escalação de Privilégios:** Como você se moveria lateralmente ou escalaria privilégios após a exploração inicial.
        *   **Passo 4 - Impacto Final:** Qual seria o objetivo final (ex: exfiltração de dados, ransomware, etc.).
    *   **Cenário 2 (Opcional): [Nome do Cenário]**
        *   ...

4.  **## Sugestões de Exploração "Fora da Caixa"**
    *   Pense em ataques criativos. Combine múltiplas vulnerabilidades de baixa severidade.
    *   Considere a lógica de negócio da aplicação.
    *   Exemplo: "A funcionalidade de upload de imagem combinada com a vulnerabilidade de SSRF na API de processamento de metadados pode permitir o escaneamento da rede interna."

5.  **## Recomendações Estratégicas**
    *   Liste as 3 principais ações que a equipe de defesa deve tomar para mitigar os riscos mais críticos identificados.

**Instruções Adicionais:**
*   Seja direto e técnico.
*   Não inclua avisos ou desculpas.
*   Foque na exploração e no impacto.
*   Se os dados forem insuficientes, aponte quais informações adicionais seriam necessárias para uma análise mais profunda.
`
}

// getADSystemPrompt define o comportamento da IA para análise de Active Directory.
func getADSystemPrompt() string {
	return `Você é um especialista em segurança de Active Directory e pentester de Red Team. Sua tarefa é analisar os resultados de ferramentas de enumeração e ataque em AD para construir uma cadeia de exploração (attack chain).

    Analise os dados a seguir (saída de ferramentas como BloodHound, CrackMapExec, Certipy, Impacket, Ruler, SharpDPAPI) e responda em formato JSON com a seguinte estrutura:
    {
      "title": "Vetor de Ataque Principal (ex: Abuso de AD CS para Domain Admin)",
      "summary": "Descreva o caminho de ataque passo a passo, correlacionando as informações. Ex: 'O usuário 'svc_exchange' possui a role 'ApplicationImpersonation' no Exchange. Isso permite o acesso a todas as caixas de correio, levando à descoberta de senhas para escalar privilégios.'",
      "attack_path": [
        {"step": 1, "action": "Comprometer o servidor MSSQL 'SQL01' usando credenciais fracas e habilitar 'xp_cmdshell' para obter execução de código como SYSTEM.", "tool": "crackmapexec"},
        {"step": 2, "action": "Executar 'mimikatz' no 'SQL01' para extrair hashes e senhas em texto plano da memória.", "tool": "mimikatz"},
        {"step": 3, "action": "Usar as credenciais de um administrador encontradas para explorar uma configuração vulnerável (ESC1) no AD CS com Certipy.", "tool": "certipy"},
        {"step": 4, "action": "Solicitar um certificado em nome de um Domain Admin e usá-lo para obter um TGT e acesso total ao domínio.", "tool": "certipy/Rubeus"}
      ],
      "severity": "Crítica | Alta | Média",
      "required_tools": ["crackmapexec", "mimikatz", "certipy", "rubeus"]
    }
    Seja direto, técnico e foque na cadeia de exploração.`
}

// AnalyzeRunResults realiza uma análise holística dos resultados de um 'run'.
func AnalyzeRunResults(ctx context.Context, taskIdentifier, initialTarget string, resultFiles []string, logger *slog.Logger) (string, error) {
	if !config.Cfg.AI.Enabled {
		return "", fmt.Errorf("AI analysis is disabled in the configuration")
	}

	logger.Info("Starting holistic AI analysis...", "target", initialTarget)

	// 1. Consolidar e formatar resultados no estilo TOON.
	var consolidatedResults strings.Builder
	consolidatedResults.WriteString(fmt.Sprintf("# Análise de Segurança para o Alvo: %s\n\n", initialTarget))

	for _, filePath := range resultFiles {
		fileName := filepath.Base(filePath)
		content, err := os.ReadFile(filePath)
		if err != nil || len(content) == 0 {
			continue // Pula arquivos vazios ou com erro de leitura
		}

		// Limita o tamanho do conteúdo para evitar exceder os limites de token
		maxSize := 15000
		isTruncated := false
		if len(content) > maxSize {
			content = content[:maxSize]
			isTruncated = true
		}

		consolidatedResults.WriteString(fmt.Sprintf("## %s\n", fileName))
		consolidatedResults.WriteString("```\n")

		// Aplica formatação TOON-like para arquivos conhecidos
		switch fileName {
		case "nuclei_scan.txt":
			findings, _ := analysis.ParseNuclei(filePath)
			if len(findings) > 0 {
				consolidatedResults.WriteString(fmt.Sprintf("nuclei_findings[%d]{template_id,name,severity,host,matched_at}:\n", len(findings)))
				for _, f := range findings {
					consolidatedResults.WriteString(fmt.Sprintf("  %s,%s,%s,%s,%s\n", f.Meta.TemplateID, f.Meta.Info.Name, f.Meta.Info.Severity, f.Meta.Host, f.Meta.MatchedAt))
				}
			}
		case "portscan_results.txt", "nmap_results.txt":
			lines := strings.Split(string(content), "\n")
			consolidatedResults.WriteString(fmt.Sprintf("open_ports[%d]{host:port}:\n", len(lines)))
			for _, line := range lines {
				if line != "" {
					consolidatedResults.WriteString(fmt.Sprintf("  %s\n", line))
				}
			}
		case "live_subdomains.txt", "recon_targets.txt", "urls.txt":
			lines := strings.Split(string(content), "\n")
			consolidatedResults.WriteString(fmt.Sprintf("targets[%d]:\n", len(lines)))
			for _, line := range lines {
				if line != "" {
					consolidatedResults.WriteString(fmt.Sprintf("  %s\n", line))
				}
			}
		case "cve_results.json":
			var cveResults []types.CVEResult
			if json.Unmarshal(content, &cveResults) == nil && len(cveResults) > 0 {
				consolidatedResults.WriteString(fmt.Sprintf("cve_findings[%d]{cve,severity,technology,url}:\n", len(cveResults)))
				for _, cve := range cveResults {
					consolidatedResults.WriteString(fmt.Sprintf("  %s,%s,%s,%s\n", cve.CVE_ID, cve.Severity, cve.Technology, cve.URL))
				}
			}
		default:
			// Para outros arquivos, apenas insere o conteúdo bruto.
			consolidatedResults.WriteString(string(content))
		}

		if isTruncated {
			consolidatedResults.WriteString("\n... (conteúdo truncado)\n")
		}
		consolidatedResults.WriteString("```\n\n")
	}

	// 2. Construir o prompt e chamar a IA
	userPrompt := consolidatedResults.String()
	systemPrompt := getHolisticSystemPrompt()

	logger.Info("Sending consolidated results to AI for holistic analysis...", "provider", config.Cfg.AI.Provider, "model", config.Cfg.AI.Model)

	aiResponse, err := queryAI(ctx, systemPrompt, userPrompt)
	if err != nil {
		return "", fmt.Errorf("failed to query AI for holistic analysis: %w", err)
	}

	return aiResponse, nil
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