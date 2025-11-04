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

type DiscordWriter struct {
	session   *discordgo.Session
	channelID string
	buffer    bytes.Buffer
	mu        sync.Mutex
}

func NewDiscordWriter(s *discordgo.Session, channelID string) *DiscordWriter {
	return &DiscordWriter{
		session:   s,
		channelID: channelID,
	}
}

func (dw *DiscordWriter) Write(p []byte) (n int, err error) {
	dw.mu.Lock()
	defer dw.mu.Unlock()

	dw.buffer.Write(p)

	if dw.buffer.Len() >= flushThreshold || bytes.Contains(p, []byte("\n")) {
		dw.Flush()
	}
	return len(p), nil
}

func (dw *DiscordWriter) Flush() {
	if dw.buffer.Len() > 0 {
		message := dw.buffer.String()
		dw.buffer.Reset()
		for len(message) > 0 {
			chunkSize := min(len(message), maxDiscordMessageLength)
			chunk := message[:chunkSize]
			_, err := dw.session.ChannelMessageSend(dw.channelID, "```\n"+chunk+"\n```")
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
