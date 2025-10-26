package discord

import (
	"bytes"
	"log/slog"
	"sync"

	"github.com/bwmarrin/discordgo"
)

const (
	maxDiscordMessageLength = 2000 // Discord's message character limit
	flushThreshold          = 1800 // Flush if buffer approaches limit
)

// DiscordWriter é um io.Writer que envia mensagens para um canal do Discord.
// Ele armazena em buffer as mensagens e as envia quando o buffer atinge um limite
// ou quando uma nova linha é encontrada.
type DiscordWriter struct {
	session   *discordgo.Session
	channelID string
	buffer    bytes.Buffer
	mu        sync.Mutex
}

// NewDiscordWriter cria uma nova instância de DiscordWriter.
func NewDiscordWriter(s *discordgo.Session, channelID string) *DiscordWriter {
	return &DiscordWriter{
		session:   s,
		channelID: channelID,
	}
}

// Write implementa a interface io.Writer.
func (dw *DiscordWriter) Write(p []byte) (n int, err error) {
	dw.mu.Lock()
	defer dw.mu.Unlock()

	dw.buffer.Write(p)

	// Flush if buffer is too large or contains a newline
	if dw.buffer.Len() >= flushThreshold || bytes.Contains(p, []byte("\n")) {
		dw.Flush()
	}
	return len(p), nil
}

// Flush envia o conteúdo atual do buffer para o Discord.
func (dw *DiscordWriter) Flush() {
	if dw.buffer.Len() > 0 {
		message := dw.buffer.String()
		dw.buffer.Reset()
		// Split message if it's too long for Discord
		for len(message) > 0 {
			chunkSize := min(len(message), maxDiscordMessageLength)
			chunk := message[:chunkSize]
			_, err := dw.session.ChannelMessageSend(dw.channelID, "```\n"+chunk+"\n```") // Use code block for formatting
			if err != nil {
				slog.Error("Failed to send Discord message", "error", err)
				break
			}
			message = message[chunkSize:]
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
