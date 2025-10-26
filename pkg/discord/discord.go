package discord

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"bytes"
	"encoding/json"
	"net/http"
	"redrecon/internal/config"
	"redrecon/pkg/recon"
	"redrecon/pkg/search"
	"time"

	"github.com/bwmarrin/discordgo"
)

var (
	botID string
)

// Command Handlers to be set by the main application to break import cycles.
var (
	StartMonitorFunc func(targets []string, frequency time.Duration)
	StartInfraFunc   func(target string, skipSteps []string, logger *slog.Logger) (string, error)
)

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

type WebhookPayload struct {
	Username  string        `json:"username"`
	Embeds    []WebhookEmbed `json:"embeds"`
}

// StartBot inicializa e inicia o bot do Discord.

// StartBot inicializa e inicia o bot do Discord.
func StartBot(token, prefix string) {
	slog.Info("Starting Discord bot...")

	dg, err := discordgo.New("Bot " + token)
	if err != nil {
		slog.Error("Error creating Discord session", "error", err)
		return
	}

	// Register the messageCreate func as a callback for MessageCreate events.
	dg.AddHandler(func(s *discordgo.Session, m *discordgo.MessageCreate) {
		messageCreate(s, m, prefix)
	})

	// In this example, we only care about receiving message events.
	dg.Identify.Intents = discordgo.IntentsGuildMessages

	// Open a websocket connection to Discord and begin listening.
	err = dg.Open()
	if err != nil {
		slog.Error("Error opening connection to Discord", "error", err)
		return
	}

	u, err := dg.User("@me")
	if err != nil {
		slog.Error("Error getting bot user info", "error", err)
		return
	}
	botID = u.ID

	slog.Info("Discord bot is now running. Press CTRL-C to exit.")

	// Wait here until CTRL-C or other term signal is received.
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt)
	<-sc

	// Cleanly close down the Discord session.
	dg.Close()
	slog.Info("Discord bot stopped.")
}

// messageCreate will be called every time a new message is sent in a channel the bot has access to.
func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate, prefix string) {
	// Ignore messages from the bot itself
	if m.Author.ID == botID || !strings.HasPrefix(m.Content, prefix) {
		return
	}

	// Create a custom logger for this command execution
	discordWriter := NewDiscordWriter(s, m.ChannelID)
	customLogger := slog.New(slog.NewTextHandler(discordWriter, &slog.HandlerOptions{
		Level: slog.LevelInfo, // Only send INFO and above to Discord
	}))

	// Parse the command
	args := strings.Fields(m.Content[len(prefix):])
	if len(args) == 0 {
		s.ChannelMessageSend(m.ChannelID, "Comando inválido. Use `!help` para ver os comandos.")
		return
	}

	command := strings.ToLower(args[0])
	cmdArgs := args[1:]

	go func() { // Run command in a goroutine to not block the bot
		defer discordWriter.Flush() // Ensure all buffered messages are sent

		switch command {
		case "recon":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!recon <target>`")
				return
			}
			targetArg := cmdArgs[0]
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("⏳ Iniciando reconhecimento para `%s`... Isso pode levar algum tempo.", targetArg))

			summary, err := recon.StartRecon(targetArg, []string{}, customLogger) // Use custom logger to send progress to Discord
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Reconhecimento para `%s` falhou: %v", targetArg, err))
			} else {
				s.ChannelMessageSend(m.ChannelID, summary)
			}
		case "infra":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!infra <target>`")
				return
			}
			targetArg := cmdArgs[0]
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("⏳ Iniciando varredura de infraestrutura para `%s`...", targetArg))
			if StartInfraFunc != nil {
				if summary, err := StartInfraFunc(targetArg, []string{}, customLogger); err != nil {
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Varredura de infraestrutura para `%s` falhou: %v", targetArg, err))
				} else {
					s.ChannelMessageSend(m.ChannelID, summary)
				}
			}
		case "monitor":
			if len(cmdArgs) < 1 {
				customLogger.Error("Uso: !monitor <target> [frequency]")
				return
			}
			targetArg := cmdArgs[0]
			freqStr := "6h" // Frequência padrão
			if len(cmdArgs) > 1 {
				freqStr = cmdArgs[1]
			}
			frequency, err := time.ParseDuration(freqStr)
			if err != nil {
				customLogger.Error("Frequência inválida. Use formatos como '1h', '30m', '12h'.", "error", err)
				return
			}
			customLogger.Info(fmt.Sprintf("Iniciando monitoramento para: %s com frequência de %s", targetArg, frequency))
			// O monitoramento é um processo longo, então apenas o iniciamos.
			// A notificação de conclusão não é aplicável aqui.
			if StartMonitorFunc != nil {
				go StartMonitorFunc([]string{targetArg}, frequency)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ Monitoramento iniciado para `%s`.", targetArg))
			}
		case "search":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!search <termo>`")
				return
			}
			searchTerm := strings.Join(cmdArgs, " ")
			// A busca é rápida, então podemos fazer de forma síncrona.
			// A flag noColor=true é para evitar caracteres de controle de cor no arquivo/mensagem.
			output, err := search.ExecuteSearch(searchTerm, "", false, false, true)
			if err != nil {
				customLogger.Error("A busca falhou", "error", err)
				return
			}
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("📄 Aqui estão os resultados da busca por: `%s`", searchTerm))
			s.ChannelFileSend(m.ChannelID, "search_results.txt", strings.NewReader(output))
		case "help":
			helpMsg := "Comandos disponíveis:\n" +
				"`!recon <target>` - Inicia um reconhecimento web completo.\n" +
				"`!infra <target>` - Inicia uma varredura de infraestrutura.\n" +
				"`!monitor <target> [frequency]` - Inicia o monitoramento contínuo (ex: `!monitor example.com 12h`).\n" +
				"`!search <termo>` - Busca por um termo em todos os resultados."
			s.ChannelMessageSend(m.ChannelID, helpMsg)
		default:
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Comando desconhecido: `%s`. Use `!help` para ver os comandos.", command))
		}
	}()
}

type WebhookEmbed struct {
	Title       string        `json:"title"`
	Description string        `json:"description"`
	Color       int           `json:"color"`
	Fields      []EmbedField  `json:"fields"`
	Footer      *EmbedFooter  `json:"footer,omitempty"`
}

type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline"`
}

type EmbedFooter struct {
	Text string `json:"text"`
}

// SendVulnerabilityNotification envia uma notificação de vulnerabilidade para o webhook configurado.
func SendVulnerabilityNotification(target string, finding NucleiFinding) {
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

	payload := WebhookPayload{
		Username: "RedRecon Monitor",
		Embeds: []WebhookEmbed{
			{
				Title:       fmt.Sprintf("🚨 Nova Vulnerabilidade: %s", finding.Info.Name),
				Description: finding.Info.Description,
				Color:       color,
				Fields: []EmbedField{
					{Name: "Alvo", Value: finding.Host, Inline: true},
					{Name: "Severidade", Value: strings.ToUpper(finding.Info.Severity), Inline: true},
					{Name: "Template", Value: finding.TemplateID, Inline: false},
				},
				Footer: &EmbedFooter{Text: fmt.Sprintf("Monitorando: %s", target)},
			},
		},
	}

	payloadBytes, _ := json.Marshal(payload)
	http.Post(webhookURL, "application/json", bytes.NewBuffer(payloadBytes))
}
