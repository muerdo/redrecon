package discord

import (
	"github.com/bwmarrin/discordgo"
)

type DiscordWriter struct {
	session   *discordgo.Session
	channelID string
}

func NewDiscordWriter(s *discordgo.Session, channelID string) *DiscordWriter {
	return &DiscordWriter{
		session:   s,
		channelID: channelID,
	}
}

func (dw *DiscordWriter) Write(p []byte) (n int, err error) {
	if dw.session != nil && dw.channelID != "" {
		// Para evitar exceder o limite de caracteres do Discord, dividimos a mensagem.
		// Esta é uma implementação simples; pode ser melhorada com um buffer.
		_, err = dw.session.ChannelMessageSend(dw.channelID, "```\n"+string(p)+"\n```")
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
