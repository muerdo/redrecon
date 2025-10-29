package discord

import (
	"fmt"
	"os/signal"
	"syscall"

	"os"
	"strings"

	"bytes"
	"encoding/json"
	"net/http"
	"redrecon/internal/config"
	"redrecon/pkg/recon"
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

// Command Handlers to be set by the main application to break import cycles.
var (
	StartMonitorFunc func(targets []string, frequency time.Duration)
	StartInfraFunc   func(taskIdentifier, target string, skipSteps []string, logger *slog.Logger) (string, []string, error)
	StartScanFunc    func(taskIdentifier, target string, skipSteps, onlySteps []string, logger *slog.Logger) (string, []string, error)
	StartWebFunc     func(taskIdentifier, target string, depth int, logger *slog.Logger) (string, []string, error)
)

// IsDiscordBotEnabled verifica se o bot do Discord está habilitado na configuração.
func IsDiscordBotEnabled() bool {
	// Esta função assume que você tem uma maneira de verificar se o bot está ativo.
	// Por exemplo, verificando se o token do bot está definido.
	return config.Cfg.Engine.Discord.Token != ""
}

// GetDiscordChannelID retorna o ID do canal para enviar mensagens.
// Isso pode ser um valor fixo ou lido da configuração.
func GetDiscordChannelID() string {
	// Supondo que você adicione um campo `ChannelID` à sua configuração do Discord.
	return config.Cfg.Engine.Discord.DefaultChannelID
}

// messageCreate will be called every time a new message is sent in a channel the bot has access to.
func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate, prefix string) {
	// Ignore messages from the bot itself
	if m.Author.ID == botID || !strings.HasPrefix(m.Content, prefix) {
		return
	}

	// Parse the command
	args := strings.Fields(m.Content[len(prefix):])
	if len(args) == 0 {
		s.ChannelMessageSend(m.ChannelID, "Comando inválido. Use `!help` para ver os comandos.")
		return
	}

	// Cria um logger padrão que escreve no console (onde o bot está rodando), não no Discord.
	// Isso mantém o canal do Discord limpo, mostrando apenas as mensagens de status.
	consoleLogger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	command := strings.ToLower(args[0])
	cmdArgs := args[1:]

	go func() { // Run command in a goroutine to not block the bot
		// defer discordWriter.Flush() // This was removed in a previous step, ensuring it stays removed.

		switch command { case "recon":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!recon <target>`")
				return
			}

			// Analisa os argumentos para encontrar o alvo e a flag --no-redirects
			var taskName string
			var targetArg string
			followRedirects := true
			for i := 0; i < len(cmdArgs); i++ {
				arg := cmdArgs[i]
				switch arg {
				case "-n", "--task-name":
					if i+1 < len(cmdArgs) {
						taskName = cmdArgs[i+1]
						i++
					}
				case "--no-redirects":
					followRedirects = false
				default:
					targetArg = arg
				}
			}

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("⏳ Iniciando reconhecimento para `%s`... Isso pode levar algum tempo.", targetArg))
			
			taskIdentifier := target.GetRootDomain(targetArg)
			if taskName != "" {
				taskIdentifier = taskName // Usa o nome da tarefa como identificador do diretório
			}
			rootTarget := target.GetRootDomain(targetArg) // O alvo real para as ferramentas

			summary, files, err := recon.StartRecon(taskIdentifier, rootTarget, []string{targetArg}, []string{}, followRedirects, false, consoleLogger)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Reconhecimento para `%s` falhou: %v", targetArg, err))
			} else {
				SendSummaryAndFiles(s, m.ChannelID, summary, files)
			}
		case "infra":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!infra <target>`")
				return
			}

			// Analisa os argumentos para encontrar o alvo e a flag --no-redirects
			var taskName string
			var targetArg string			
			for i := 0; i < len(cmdArgs); i++ {
				arg := cmdArgs[i]
				switch arg {
				case "-n", "--task-name":
					if i+1 < len(cmdArgs) {
						taskName = cmdArgs[i+1]
						i++
					}
				default:
					if targetArg == "" {
						targetArg = arg
					}
				}
			}

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("⏳ Iniciando varredura de infraestrutura para `%s`...", targetArg))
			if StartInfraFunc != nil {
				if summary, files, err := StartInfraFunc(taskName, targetArg, []string{}, consoleLogger); err != nil { // Passa taskName e targetArg
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Varredura de infraestrutura para `%s` falhou (Task: %s): %v", targetArg, taskName, err))
				} else {
					SendSummaryAndFiles(s, m.ChannelID, summary, files)
				}
			}
		case "monitor":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!monitor <target> [frequency]`")
				return
			}
			
			// Extrai alvos e frequência. A frequência é o último argumento se for uma duração válida.
			var targets []string
			freqStr := "6h" // Frequência padrão
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

			frequency, _ := time.ParseDuration(freqStr) // O erro já foi verificado
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
			
			var searchTermParts []string // Usar um slice para coletar partes do termo de busca
			var targetScope string
			var listOnly, useRegex bool

			// Itera sobre os argumentos para encontrar flags e o termo de busca
			for i := 0; i < len(cmdArgs); i++ {
				arg := cmdArgs[i]
				switch arg {
				case "-t", "--target": // Suporta -t e --target
					if i+1 < len(cmdArgs) {
						targetScope = cmdArgs[i+1]
						i++ // Pula o próximo argumento, pois já foi consumido
					} else {
						s.ChannelMessageSend(m.ChannelID, "Erro: A flag `-t` ou `--target` requer um valor para o alvo.")
						return
					}
				case "-l", "--list-only": // Suporta -l e --list-only
					listOnly = true
				case "-r", "--regex": // Suporta -r e --regex
					useRegex = true
				default:
					// Coleta argumentos que não são flags como partes do termo de busca
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
			
			// A função de busca já está preparada para não usar cores fora do terminal
			output, err := search.ExecuteSearch(searchTerm, targetScope, listOnly, useRegex)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ A busca falhou: %v", err))
			} else {
				fileName := fmt.Sprintf("search_results_%s.txt", recon.SanitizeTargetForPath(searchTerm))
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

		case "scan":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!scan <alvo> [--skip step] [--only step]`")
				return
			}

			var taskName string
			var targetArg string
			var skipSteps []string
			var onlySteps []string
			for i, arg := range cmdArgs {
				switch arg {
				case "-n", "--task-name":
					if i+1 < len(cmdArgs) {
						taskName = cmdArgs[i+1]
						i++
					}
				case "--skip":
					if i+1 < len(cmdArgs) {
						skipSteps = strings.Split(cmdArgs[i+1], ",")
						i++ // Pula o próximo argumento
					}
				case "--only":
					if i+1 < len(cmdArgs) {
						onlySteps = strings.Split(cmdArgs[i+1], ",")
						i++ // Pula o próximo argumento
					}
				default:
					if targetArg == "" {
						targetArg = arg
					}
				}
			}

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("⏳ Iniciando varredura de vulnerabilidades para `%s`...", targetArg))
			if StartScanFunc != nil {
				taskIdentifier := target.GetRootDomain(targetArg)
				if taskName != "" {
					taskIdentifier = taskName
				}
				summary, files, err := StartScanFunc(taskIdentifier, targetArg, skipSteps, onlySteps, consoleLogger)
				if err != nil {
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Varredura para `%s` falhou (Task: %s): %v", targetArg, taskIdentifier, err))
				} else {
					SendSummaryAndFiles(s, m.ChannelID, summary, files)
				}
			}

		case "chain":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!chain <alvo> [-n task_name]`")
				return
			}

			var taskName string
			var targetArg string
			for i, arg := range cmdArgs {
				switch arg {
				case "-n", "--task-name":
					if i+1 < len(cmdArgs) {
						taskName = cmdArgs[i+1]
						i++
					}
				default:
					if targetArg == "" {
						targetArg = arg
					}
				}
			}

			taskIdentifier := target.GetRootDomain(targetArg)
			if taskName != "" {
				taskIdentifier = taskName
			}
			rootTarget := target.GetRootDomain(targetArg) // O alvo real para as ferramentas

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🔗 **Iniciando fluxo 'chain' para `%s` (Task: `%s`)**\n\nFase 1: Reconhecimento...", targetArg, taskIdentifier))
			reconSummary, reconFiles, err := recon.StartRecon(taskIdentifier, rootTarget, []string{targetArg}, []string{}, true, false, consoleLogger)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Fase de Reconhecimento falhou para `%s`: %v", targetArg, err))
				return
			}
			SendSummaryAndFiles(s, m.ChannelID, reconSummary, reconFiles)

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ Reconhecimento concluído. Iniciando Fase 2: Varredura de Vulnerabilidades..."))
			scanSummary, scanFiles, err := StartScanFunc(taskIdentifier, targetArg, []string{}, []string{}, consoleLogger)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Fase de Varredura falhou para `%s`: %v", targetArg, err))
			} else {
				SendSummaryAndFiles(s, m.ChannelID, scanSummary, scanFiles)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ **Fluxo 'chain' para `%s` concluído com sucesso!**", targetArg))
			}

		case "web":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!web <url> [-d depth] [-n task_name]`")
				return
			}

			var taskName string
			var targetArg string
			depth := 2 // Profundidade padrão
			for i := 0; i < len(cmdArgs); i++ {
				arg := cmdArgs[i]
				switch arg {
				case "-n", "--task-name":
					if i+1 < len(cmdArgs) {
						taskName = cmdArgs[i+1]
						i++
					}
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
			if taskName != "" {
				taskIdentifier = taskName
			}

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🕸️ Iniciando rastreamento e análise web para `%s` (Profundidade: %d)...", targetArg, depth))
			summary, files, err := StartWebFunc(taskIdentifier, targetArg, depth, consoleLogger)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Análise web para `%s` falhou: %v", targetArg, err))
			} else {
				SendSummaryAndFiles(s, m.ChannelID, summary, files)
			}

		case "help":
			helpMsg := "Comandos disponíveis:\n" +
				"`!recon <target>` - Inicia um reconhecimento web completo.\n" +
				"`!infra <target>` - Inicia uma varredura de infraestrutura.\n" +
				"`!scan <target>` - Inicia uma varredura de vulnerabilidades.\n" +
				"`!chain <target>` - Executa 'recon' seguido de 'scan'.\n" +
				"`!web <url>` - Rastreia e analisa um site específico. Flags: `-d <profundidade>`, `-n <nome>`.\n" +
				"`!monitor <target> [frequency]` - Inicia o monitoramento contínuo (ex: `!monitor example.com 12h`).\n" +
				"  - Todos os comandos (`recon`, `scan`, `infra`) aceitam a flag `-n <nome>` ou `--task-name <nome>` para agrupar resultados.\n" +
				"`!search <termo> [flags]` - Procura por um termo nos resultados.\n" +
				"  - Flags: `-t <alvo>` (para buscar apenas em um alvo), `-l` (listar arquivos), `-r` (usar Regex).\n" +
				"  - Exemplo: `!search \"api_key\" -t example.com -r`"
			s.ChannelMessageSend(m.ChannelID, helpMsg)
		case "results":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!results <alvo>`")
				return
			}
			targetArg := cmdArgs[0]
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🔎 Buscando resultados para o alvo `%s`...", targetArg))

			summary, files, err := getTargetResults(targetArg)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Erro ao buscar resultados para `%s`: %v", targetArg, err))
			} else if len(files) == 0 {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🤷 Nenhum arquivo de resultado encontrado para `%s`.", targetArg))
			} else {
				SendSummaryAndFiles(s, m.ChannelID, summary, files) // This was missing a closing brace in the original context, fixed here.
			}
		default:
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Comando desconhecido: `%s`. Use `!help` para ver os comandos.", command))
		}
	}()
}

func (b *bot) handleInfraCommand(s *discordgo.Session, m *discordgo.MessageCreate, cmdArgs []string, consoleLogger *slog.Logger) {
	// ... (implementação futura, se necessário)
}

type bot struct {
	// ... (campos futuros, se necessário)
}

func NewBot() *bot {
	return &bot{}
}


// getTargetResults localiza e lista todos os arquivos de resultado para um determinado alvo.
func getTargetResults(target string) (string, []string, error) {
	sanitizedTarget := recon.SanitizeTargetForPath(target)
	targetResultsPath := filepath.Join("results", sanitizedTarget)

	if _, err := os.Stat(targetResultsPath); os.IsNotExist(err) {
		return "", nil, fmt.Errorf("diretório de resultados para o alvo não encontrado")
	}

	var files []string
	err := filepath.Walk(targetResultsPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Adiciona apenas arquivos, não diretórios.
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

// SendSummaryAndFiles envia a mensagem de sumário e anexa os arquivos de resultado.
func SendSummaryAndFiles(s *discordgo.Session, channelID, summary string, files []string) {
	// Se a sessão 's' for nula (quando chamada de fora do bot), não podemos enviar mensagens.
	// Isso é um placeholder. Uma solução melhor seria usar um cliente Discord global.
	if s == nil || channelID == "" {
		slog.Warn("Discord session or channel ID is not available. Cannot send results.")
		return
	}
	// 1. Envia a mensagem de sumário primeiro.
	_, err := s.ChannelMessageSend(channelID, summary)
	if err != nil {
		slog.Error("Failed to send summary message to Discord", "error", err)
		// Continua mesmo se o sumário falhar, para tentar enviar os arquivos.
	}

	// 2. Itera sobre cada arquivo de resultado e envia seu conteúdo.
	// Envia cada arquivo como um anexo separado para melhor clareza e para evitar limites de tamanho de mensagem.
	for _, filePath := range files {
		// Pula arquivos que não existem ou estão vazios.
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

		// Envia o arquivo como um anexo.
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

// SendWebhookNotification envia uma notificação via webhook, ideal para processos de background como o 'chain'.
func SendWebhookNotification(title, description string, color int, fields []types.EmbedField) {
	webhookURL := config.Cfg.Engine.Discord.WebhookURL
	if webhookURL == "" {
		slog.Warn("Discord webhook URL is not configured. Cannot send notification.")
		return
	}

	if color == 0 {
		color = 0x4E5D94 // Cor padrão do RedRecon
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

// SendVulnerabilityNotification envia uma notificação de vulnerabilidade para o webhook configurado.
func SendVulnerabilityNotification(target string, finding types.NucleiFinding) {
	webhookURL := config.Cfg.Engine.Discord.WebhookURL
	if webhookURL == "" {
		return
	}

	color := 0xDBA800 // Amarelo para severidade média (padrão)
	switch strings.ToUpper(finding.Info.Severity) {
	case "CRITICAL":
		color = 0x992D22 // Vermelho escuro
	case "HIGH":
		color = 0xE53935 // Vermelho
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

// StartBot initializes and starts the Discord bot.
func StartBot(token, prefix string) {
	// Create a new Discord session using the provided bot token.
	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		slog.Error("error creating Discord session,", "error", err)
		return
	}

	// Define um cliente HTTP customizado com um timeout maior para lidar com redes lentas.
	dg.Client = &http.Client{Timeout: 30 * time.Second}

	// Get the bot's user ID
	slog.Info("Connecting to Discord and verifying bot token...")
	u, err := dg.User("@me")
	if err != nil {
		slog.Error("error obtaining account details,", "error", err)
		return
	}
	botID = u.ID

	// Register the messageCreate func as a callback for MessageCreate events.
	dg.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		messageCreate(s, m, prefix)
	})

	// We only care about receiving message events.
	dg.Identify.Intents = discordgo.IntentsGuildMessages

	// Open a websocket connection to Discord and begin listening.
	err = dg.Open()
	if err != nil {
		slog.Error("error opening connection,", "error", err)
		return
	}

	// Wait here until CTRL-C or other term signal is received.
	slog.Info("Bot is now running. Press CTRL-C to exit.")
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	// Cleanly close down the Discord session.
	dg.Close()
}
