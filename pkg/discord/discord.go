package discord

import (
	"fmt"
	"context"
	"os/signal"
	"syscall"

	"os"
	"strings"

	"bytes"
	"encoding/json"
	"net/http"
	"redrecon/internal/config"
	"redrecon/pkg/utils"
	"redrecon/pkg/taskmanager"
	"redrecon/pkg/target"
	"redrecon/pkg/types"
	"redrecon/pkg/search"
	"time"
	"log/slog"
	"path/filepath"

	"github.com/bwmarrin/discordgo"
)

var (
	botID string
)

var (
	StartMonitorFunc func(targets []string, frequency time.Duration)
	StartReconFunc   func(taskIdentifier, rootTarget string, initialSubdomains, skipSteps []string, skipAnalysis, followRedirects, isInteractive, useResolvedForScan bool, logger *slog.Logger) (string, []string, bool, error)
	StartRunFunc     func(ctx context.Context, initialTarget string, reconSkipSteps, scanSkipSteps, scanOnlySteps []string, isAggressive, skipAnalysis, forceScan bool, logger *slog.Logger) (string, []string, error)
	StartInfraFunc   func(taskIdentifier, target string, skipSteps []string, logger *slog.Logger) (string, []string, error)
	StartScanFunc    func(ctx context.Context, taskIdentifier string, skipSteps, onlySteps []string, isAggressive, isInteractive bool, logger *slog.Logger) (string, []string, error)
	StartWebFunc     func(taskIdentifier, target string, depth int, logger *slog.Logger) (string, []string, error)
	StartAPIFunc     func(taskIdentifier string, skipSteps []string, logger *slog.Logger) (string, []string, error)
)

func IsDiscordBotEnabled() bool {
	return config.Cfg.Engine.Discord.Token != ""
}

func GetDiscordChannelID() string {
	return config.Cfg.Engine.Discord.DefaultChannelID
}

func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate, prefix string) {
	if m.Author.ID == botID || !strings.HasPrefix(m.Content, prefix) {
		return
	}

	args := strings.Fields(m.Content[len(prefix):])
	if len(args) == 0 {
		s.ChannelMessageSend(m.ChannelID, "Comando inválido. Use `!help` para ver os comandos.")
		return
	}

	command := strings.ToLower(args[0])
	cmdArgs := args[1:]

	go func() {
		discordWriter := NewDiscordWriter(s, m.ChannelID)
		discordLogger := slog.New(slog.NewTextHandler(discordWriter, nil))
		defer discordWriter.Flush()

		switch command {
		case "monitor":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!monitor <target> [frequency]`")
				return
			}
			
			var targets []string
			freqStr := "6h"
			lastArg := cmdArgs[len(cmdArgs)-1]
			
			if _, err := time.ParseDuration(lastArg); err == nil {
				freqStr = lastArg
				targets = cmdArgs[:len(cmdArgs)-1]
			} else {
				targets = cmdArgs
			}

			if len(targets) == 0 {
				s.ChannelMessageSend(m.ChannelID, "Nenhum alvo especificado para o monitoramento.")
				return
			}

			frequency, _ := time.ParseDuration(freqStr)
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Iniciando monitoramento para: `%s` com frequência de %s", strings.Join(targets, ", "), frequency))
			if StartMonitorFunc != nil {
				go StartMonitorFunc(targets, frequency)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ Monitoramento iniciado para `%d` alvo(s).", len(targets)))
			}
		case "search":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!search <termo>`")
				return
			}
			
			var searchTermParts []string
			var targetScope string
			var listOnly, useRegex bool

			for i := 0; i < len(cmdArgs); i++ {
				arg := cmdArgs[i]
				switch arg {
				case "-t", "--target":
					if i+1 < len(cmdArgs) {
						targetScope = cmdArgs[i+1]
						i++
					} else {
						s.ChannelMessageSend(m.ChannelID, "Erro: A flag `-t` ou `--target` requer um valor para o alvo.")
						return
					}
				case "-l", "--list-only":
					listOnly = true
				case "-r", "--regex":
					useRegex = true
				default:
					searchTermParts = append(searchTermParts, arg)
				}
			}

			searchTerm := strings.Join(searchTermParts, " ")
			if searchTerm == "" {
				s.ChannelMessageSend(m.ChannelID, "Erro: O termo de busca não pode ser vazio.")
				return
			}

			searchScopeMsg := "todos os resultados"
			if targetScope != "" {
				searchScopeMsg = fmt.Sprintf("resultados do alvo `%s`", targetScope)
			}
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🔎 Procurando por `%s` em %s...", searchTerm, searchScopeMsg))
			
			output, err := search.ExecuteSearch(searchTerm, targetScope, listOnly, useRegex)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ A busca falhou: %v", err))
			} else {
				fileName := fmt.Sprintf("search_results_%s.txt", utils.SanitizeTargetForPath(searchTerm))
				s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{
					Content: "Resultados da busca:",
					Files: []*discordgo.File{
						{
							Name:   fileName,
							Reader: strings.NewReader(output),
						},
					},
				})
			}

		case "run":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!run <alvo> [--recon-skip <steps>] [--scan-skip <steps>] [--scan-only <steps>] [--aggressive] [--skip-analysis] [--force-scan]`")
				return
			}

			var (
				runTarget         string
				reconSkipSteps    []string
				scanSkipSteps     []string
				scanOnlySteps     []string
				isAggressive      bool
				skipAnalysis      bool
				forceScan         bool
			)

			runTarget = cmdArgs[0]

			for i := 1; i < len(cmdArgs); i++ {
				arg := cmdArgs[i]
				switch arg {
				case "--recon-skip":
					if i+1 < len(cmdArgs) {
						reconSkipSteps = strings.Split(cmdArgs[i+1], ",")
						i++
					}
				case "--scan-skip":
					if i+1 < len(cmdArgs) {
						scanSkipSteps = strings.Split(cmdArgs[i+1], ",")
						i++
					}
				case "--scan-only":
					if i+1 < len(cmdArgs) {
						scanOnlySteps = strings.Split(cmdArgs[i+1], ",")
						i++
					}
				case "--aggressive":
					isAggressive = true
				case "--skip-analysis":
					skipAnalysis = true
				case "--force-scan":
					forceScan = true
				default:
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Argumento desconhecido para !run: `%s`", arg))
					return
				}
			}

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🚀 Iniciando fluxo completo para o alvo: `%s`...", runTarget))

			if StartRunFunc != nil {
				summary, files, err := StartRunFunc(context.Background(), runTarget, reconSkipSteps, scanSkipSteps, scanOnlySteps, isAggressive, skipAnalysis, forceScan, discordLogger)
				if err != nil {
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ O fluxo 'run' para `%s` falhou: %v", runTarget, err))
				} else {
					SendSummaryAndFiles(s, m.ChannelID, summary, files)
				}
			} else {
				s.ChannelMessageSend(m.ChannelID, "Erro interno: A função 'run' não está configurada.")
			}

		case "web":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!web <url> [-d depth] [-n task_name]`")
				return
			}

			var targetArg string
			depth := 2
			for i := 0; i < len(cmdArgs); i++ {
				arg := cmdArgs[i]
				switch arg {
				case "-d", "--depth":
					if i+1 < len(cmdArgs) {
						fmt.Sscanf(cmdArgs[i+1], "%d", &depth)
						i++
					}
				default:
					if targetArg == "" {
						targetArg = arg
					}
				}
			}

			taskIdentifier := target.GetRootDomain(targetArg)
			
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🕸️ Iniciando rastreamento e análise web para `%s` (Profundidade: %d)...", targetArg, depth))
			summary, files, err := StartWebFunc(taskIdentifier, targetArg, depth, discordLogger)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Análise web para `%s` falhou: %v", targetArg, err))
			} else {
				SendSummaryAndFiles(s, m.ChannelID, summary, files)
			}
		case "infra":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!infra <alvo>`")
				return
			}
			targetArg := cmdArgs[0]
			taskIdentifier := target.GetRootDomain(targetArg)

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🏗️ Iniciando varredura de infraestrutura para `%s`...", targetArg))
			summary, files, err := StartInfraFunc(taskIdentifier, targetArg, []string{}, discordLogger)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Varredura de infra para `%s` falhou: %v", targetArg, err))
			} else {
				SendSummaryAndFiles(s, m.ChannelID, summary, files)
			}
		case "api":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!api <task_name>`")
				return
			}
			taskIdentifier := cmdArgs[0]

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🔎 Iniciando varredura de API para a tarefa `%s`...", taskIdentifier))
			summary, files, err := StartAPIFunc(taskIdentifier, []string{}, discordLogger)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Varredura de API para `%s` falhou: %v", taskIdentifier, err))
			} else {
				SendSummaryAndFiles(s, m.ChannelID, summary, files)
			}
		case "status":
			s.ChannelMessageSend(m.ChannelID, "📊 Verificando status das tarefas...")
			resultsDir := "results"
			entries, err := os.ReadDir(resultsDir)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, "❌ Erro ao ler o diretório de resultados.")
				return
			}

			var tasks []string
			for _, entry := range entries {
				if entry.IsDir() {
					tasks = append(tasks, entry.Name())
				}
			}

			if len(tasks) == 0 {
				s.ChannelMessageSend(m.ChannelID, "🤷 Nenhuma tarefa encontrada no diretório de resultados.")
				return
			}

			var response strings.Builder
			response.WriteString("**Tarefas com Resultados (Iniciadas/Concluídas):**\n")
			for _, task := range tasks {
				response.WriteString(fmt.Sprintf("- `%s`\n", task))
			}
			s.ChannelMessageSend(m.ChannelID, response.String())

		case "results":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!results <alvo> [--partial]`")
				return
			}
			targetArg := cmdArgs[0]
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🔎 Buscando resultados para o alvo `%s`...", targetArg))

			summary, files, err := getTargetResults(targetArg)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Erro ao buscar resultados para `%s`: %v", targetArg, err))
			} else if len(files) == 0 {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🤷 Nenhum resultado encontrado para o alvo `%s`.", targetArg))
			} else {
				SendSummaryAndFiles(s, m.ChannelID, summary, files)
			}
		
		case "stop":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!stop <nome_da_tarefa>`")
				return
			}
			taskIdentifier := cmdArgs[0]
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🛑 Tentando cancelar a tarefa: `%s`...", taskIdentifier))

			if err := taskmanager.StopTask(taskIdentifier); err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("⚠️ Não foi possível cancelar a tarefa: %v", err))
			} else {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ Tarefa `%s` cancelada com sucesso.", taskIdentifier))
			}

		case "help":
			helpMsg := "Comandos disponíveis:\n" +
				"`!run <target>` - Executa um fluxo completo de reconhecimento e varredura.\n" +
				"`!stop <task_name>` - Cancela uma tarefa em andamento (ex: `!stop example.com`).\n" +
				"`!infra <target>` - Inicia uma varredura de infraestrutura.\n" +
				"`!api <task_name>` - Inicia uma varredura de API baseada nos resultados de uma tarefa existente.\n" +
				"`!web <url>` - Rastreia e analisa um site específico. Flags: `-d <profundidade>`.\n" +
				"`!monitor <target> [frequency]` - Inicia o monitoramento contínuo (ex: `!monitor example.com 12h`).\n" +
				"`!status` - Lista todas as tarefas com resultados existentes.\n" +
				"`!results <alvo> [--partial]` - Mostra o resumo e os arquivos de uma tarefa (mesmo que em andamento).\n" +
				"`!search <termo> [flags]` - Procura por um termo nos resultados.\n" +
				"  - Flags: `-t <alvo>` (para buscar apenas em um alvo), `-l` (listar arquivos), `-r` (usar Regex).\n" +
				"  - Exemplo: `!search \"api_key\" -t example.com -r`"
			s.ChannelMessageSend(m.ChannelID, helpMsg)
		default:
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Comando desconhecido: `%s`. Use `!help` para ver os comandos.", command))
		}
	}()
}

func (b *bot) handleInfraCommand(s *discordgo.Session, m *discordgo.MessageCreate, cmdArgs []string, consoleLogger *slog.Logger) {
	// ... (implementação futura, se necessário)
}

type bot struct{}

func NewBot() *bot {
	return &bot{}
}


func getTargetResults(target string) (string, []string, error) {
	sanitizedTarget := utils.SanitizeTargetForPath(target)
	targetResultsPath := filepath.Join("results", sanitizedTarget)

	if _, err := os.Stat(targetResultsPath); os.IsNotExist(err) {
		return "", nil, fmt.Errorf("diretório de resultados para o alvo não encontrado")
	}

	var files []string
	err := filepath.Walk(targetResultsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return "", nil, fmt.Errorf("falha ao percorrer o diretório de resultados: %w", err)
	}

	summary := fmt.Sprintf("✅ **Resumo dos Resultados para: %s**\n\nEncontrados `%d` arquivos de resultado. Enviando como anexos...", target, len(files))

	return summary, files, nil
}

func SendSummaryAndFiles(s *discordgo.Session, channelID, summary string, files []string) {
	if s == nil || channelID == "" {
		slog.Warn("Discord session or channel ID is not available. Cannot send results.")
		return
	}
	_, err := s.ChannelMessageSend(channelID, summary)
	if err != nil {
		slog.Error("Failed to send summary message to Discord", "error", err)
	}

	for _, filePath := range files {
		stat, err := os.Stat(filePath)
		if os.IsNotExist(err) || (err == nil && stat.Size() == 0) {
			continue
		}

		file, err := os.Open(filePath)
		if err != nil {
			slog.Warn("Could not open result file to send to Discord", "file", filePath, "error", err)
			continue
		}
		defer file.Close()

		_, err = s.ChannelMessageSendComplex(channelID, &discordgo.MessageSend{
			Content: fmt.Sprintf("📄 **Resultado do arquivo: `%s`**", filepath.Base(filePath)),
			Files: []*discordgo.File{
				{
					Name:   filepath.Base(filePath),
					Reader: file,
				},
			},
		})
		if err != nil {
			slog.Warn("Failed to send file to Discord", "file", filePath, "error", err)
		}
	}
}

func SendWebhookNotification(title, description string, color int, fields []types.EmbedField) {
	webhookURL := config.Cfg.Engine.Discord.WebhookURL
	if webhookURL == "" {
		slog.Warn("Discord webhook URL is not configured. Cannot send notification.")
		return
	}

	if color == 0 {
		color = 0x4E5D94
	}

	payload := types.WebhookPayload{
		Username: "RedRecon Chain",
		Embeds: []types.WebhookEmbed{
			{
				Title:       title,
				Description: description,
				Color:       color,
				Fields:      fields,
				Footer:      &types.EmbedFooter{Text: "Chain command finished"},
			},
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		slog.Error("Failed to marshal webhook payload", "error", err)
		return
	}

	http.Post(webhookURL, "application/json", bytes.NewBuffer(payloadBytes))
	slog.Info("Sent notification to Discord webhook.")
}

func SendVulnerabilityNotification(target string, finding types.NucleiFinding) {
	webhookURL := config.Cfg.Engine.Discord.WebhookURL
	if webhookURL == "" {
		return
	}

	color := 0xDBA800
	switch strings.ToUpper(finding.Info.Severity) {
	case "CRITICAL":
		color = 0x992D22
	case "HIGH":
		color = 0xE53935
	case "LOW":
		color = 0x43A047 // Verde
	case "INFO":
		color = 0x1E88E5 // Azul
	}

	payload := types.WebhookPayload{
		Username: "RedRecon Monitor",
		Embeds: []types.WebhookEmbed{
			{
				Title:       fmt.Sprintf("🚨 Nova Vulnerabilidade: %s", finding.Info.Name),
				Description: finding.Info.Description,
				Color:       color,
				Fields: []types.EmbedField{
					{Name: "Alvo", Value: finding.Host, Inline: true},
					{Name: "Severidade", Value: strings.ToUpper(finding.Info.Severity), Inline: true},
					{Name: "Template", Value: finding.TemplateID, Inline: false},
				},
				Footer: &types.EmbedFooter{Text: fmt.Sprintf("Monitorando: %s", target)},
			},
		},
	}

	payloadBytes, _ := json.Marshal(payload)
	http.Post(webhookURL, "application/json", bytes.NewBuffer(payloadBytes))
}

func StartBot(token, prefix string) {
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		slog.Error("error creating Discord session,", "error", err)
		return
	}

	dg.Client = &http.Client{Timeout: 60 * time.Second}

	slog.Info("Connecting to Discord and verifying bot token...")
	u, err := dg.User("@me")
	if err != nil {
		slog.Error("error obtaining account details,", "error", err)
		return
	}
	botID = u.ID

	dg.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		messageCreate(s, m, prefix)
	})

	dg.Identify.Intents = discordgo.IntentsGuildMessages

	err = dg.Open()
	if err != nil {
		slog.Error("error opening connection,", "error", err)
		return
	}

	slog.Info("Bot is now running. Press CTRL-C to exit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	dg.Close()
}
