package discord

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"os"
	"strings"

	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"redrecon/internal/config"
	"redrecon/pkg/monitor"
	"redrecon/pkg/search"
	"redrecon/pkg/target"
	"redrecon/pkg/taskmanager"
	"redrecon/pkg/tools"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
	"sync"
	"time"

	"github.com/bwmarrin/discordgo"
)

var (
	// Sessão global para ser acessível por outras partes da aplicação
	dg    *discordgo.Session
	botID string

	// Funções de callback para iniciar os fluxos de trabalho
	StartMonitorFunc func(targets []string, frequency time.Duration)
	StartReconFunc   func(taskIdentifier, rootTarget string, initialSubdomains, skipSteps, bbotPresets, bbotModules []string, skipAnalysis, followRedirects, isInteractive, useResolvedForScan, downloadContent bool, logger *slog.Logger) (string, []string, bool, error)
	StartRunFunc     func(ctx context.Context, taskIdentifier, initialTarget string, reconSkipSteps, scanSkipSteps, scanOnlySteps []string, bbotModules, bbotPresets, nucleiGroup string, isAggressive, skipAnalysis, followRedirects, forceScan, downloadContent bool, logger *slog.Logger) (string, []string, error)
	StartInfraFunc   func(taskIdentifier, target string, skipSteps, bbotPresets, bbotModules []string, logger *slog.Logger) (string, []string, error)
	StartScanFunc    func(ctx context.Context, taskIdentifier, inputFile string, skipSteps, onlySteps, bbotPresets, bbotModules []string, nucleiGroup string, isAggressive, isInteractive bool, logger *slog.Logger) (string, []string, error)
	StartWebFunc     func(taskIdentifier, target string, depth int, allowSubdomains bool, bbotPreset string, proxyManager *utils.ProxyManager, logger *slog.Logger) (string, []string, error)
	StartAPIFunc     func(taskIdentifier string, skipSteps, bbotPresets, bbotModules []string, logger *slog.Logger) (string, []string, error)
)

func IsDiscordBotEnabled() bool {
	return config.Cfg.Engine.Discord.Token != ""
}

func GetDiscordChannelID() string {
	return config.Cfg.Engine.Discord.DefaultChannelID
}

// messageCreate é o handler principal que agora inclui uma camada de autorização.
func messageCreate(s *discordgo.Session, m *discordgo.MessageCreate) {
	prefix := config.Cfg.Engine.Discord.Prefix
	if m.Author.ID == s.State.User.ID || !strings.HasPrefix(m.Content, prefix) {
		return
	}

	// 1. Verificação de autorização em paralelo
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authChan := make(chan bool, 1)
	go func() {
		authChan <- isAuthorized(s, m)
		close(authChan)
	}()

	select {
	case authorized := <-authChan:
		if !authorized {
			securityConfig := config.Cfg.Engine.Discord.Security
			s.ChannelMessageSend(m.ChannelID, securityConfig.DenyMessage)
			if securityConfig.LogUnauthorized {
				SendWebhookNotification("Tentativa de Comando Não Autorizada",
					fmt.Sprintf("Usuário: `%s`\nComando: `%s`", m.Author.Username, m.Content),
					0xff0000, nil)
			}
			return
		}
	case <-ctx.Done():
		s.ChannelMessageSend(m.ChannelID, "Timeout na verificação de acesso. Tente novamente.")
		return
	}

	// 2. Processa o comando se autorizado
	content := strings.TrimPrefix(m.Content, prefix)
	args := strings.Fields(content)
	if len(args) == 0 {
		return
	}
	command := strings.ToLower(args[0])
	cmdArgs := args[1:]

	// A lógica de processamento do comando foi movida para sua própria função
	processCommand(s, m, command, cmdArgs)
}

// processCommand contém a lógica do switch para lidar com os diferentes comandos do bot.
func processCommand(s *discordgo.Session, m *discordgo.MessageCreate, command string, cmdArgs []string) {
	go func() {
		switch command {
		case "monitor":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!monitor <add|status|stop> [args...]`")
				return
			}
			subCommand := cmdArgs[0]
			subArgs := cmdArgs[1:]

			switch subCommand {
			case "add":
				if len(subArgs) == 0 {
					s.ChannelMessageSend(m.ChannelID, "Uso: `!monitor add <alvo1> <alvo2>...`")
					return
				}
				monitor.AddTargets(subArgs)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("✅ Alvo(s) adicionado(s) ao monitor: `%s`", strings.Join(subArgs, ", ")))
			case "remove":
				if len(subArgs) == 0 {
					s.ChannelMessageSend(m.ChannelID, "Uso: `!monitor remove <alvo1> <alvo2>...`")
					return
				}
				removed := monitor.RemoveTargets(subArgs)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🗑️ Alvo(s) removido(s) do monitor: `%s`", strings.Join(removed, ", ")))
			case "status":
				statusMsg := monitor.GetStatus()
				s.ChannelMessageSend(m.ChannelID, statusMsg)
			case "stop":
				if err := monitor.Stop(); err != nil {
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("⚠️ Erro ao parar o monitor: %v", err))
				} else {
					s.ChannelMessageSend(m.ChannelID, "🛑 Monitoramento parado com sucesso.")
				}
			case "start": // Mantém a capacidade de iniciar/reiniciar
				freqStr := config.Cfg.Monitor.Frequency
				if len(subArgs) > 0 {
					if _, err := time.ParseDuration(subArgs[0]); err == nil {
						freqStr = subArgs[0]
					}
				}
				frequency, _ := time.ParseDuration(freqStr)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("▶️ Iniciando/Reiniciando o processo de monitoramento com frequência de %s...", frequency))
				go monitor.Start(nil, frequency) // Passa nil para usar os alvos já salvos no estado
			default:
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Subcomando desconhecido para `!monitor`: `%s`. Use `add`, `remove`, `status`, `start` ou `stop`.", subCommand))
			}
		case "exploit":
			discordWriter := NewDiscordWriter(s, m.ChannelID)
			logger := slog.New(slog.NewTextHandler(discordWriter, nil))

			if len(cmdArgs) < 2 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!exploit <module> <host> [tech]`")
				return
			}
			module, host, tech := cmdArgs[0], cmdArgs[1], ""
			if len(cmdArgs) > 2 {
				tech = cmdArgs[2]
			}

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("💣 Tentando explorar `%s` com o módulo `%s`...", host, module))

			msf, err := tools.NewMetasploit(context.Background(), logger)
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Falha ao conectar com o Metasploit: %v", err))
				return
			}

			out, err := msf.RunExploit(host, module, map[string]string{"tech": tech})
			if err != nil {
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Exploit falhou: %v", err))
				return
			}
			// Extrai a evidência do primeiro achado de segredo (que contém o output do exploit)
			var evidence string
			if len(out.Secrets) > 0 {
				// Asserção de tipo para acessar a struct concreta.
				// O resultado do exploit é um *types.MetasploitFinding.
				if mf, ok := out.Secrets[0].(*types.MetasploitFinding); ok {
					evidence = mf.Evidence
				}
			}
			SendSummaryAndFiles(s, m.ChannelID, fmt.Sprintf("```\n%s\n```", evidence), nil) // Envia a evidência como resumo
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

			output, err := search.ExecuteSearch(searchTerm, targetScope, listOnly, useRegex, nil, nil)
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
				s.ChannelMessageSend(m.ChannelID, "Uso: `!run <alvo> [flags...]`\nFlags: `--with-infra`, `--with-web`, `--recon-skip`, etc.")
				return
			}

			var (
				runTarget       string
				withInfra       bool
				withWeb         bool
				reconSkipSteps  []string
				scanSkipSteps   []string
				scanOnlySteps   []string
				isAggressive    bool
				skipAnalysis    bool
				forceScan       bool
				bbotModules     string
				nucleiGroup     string
				bbotPresets     string // Nova flag para presets do bbot
				verbose         bool   // Nova flag para logs detalhados
				downloadContent bool
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
				case "--with-infra":
					withInfra = true
				case "--with-web":
					withWeb = true
				case "--bbot-modules":
					if i+1 < len(cmdArgs) {
						bbotModules = cmdArgs[i+1]
						i++
					}
				case "--nuclei-group":
					if i+1 < len(cmdArgs) {
						nucleiGroup = cmdArgs[i+1]
						i++
					}
				case "--bbot-presets":
					if i+1 < len(cmdArgs) {
						bbotPresets = cmdArgs[i+1]
						i++
					}
				case "--verbose":
					verbose = true
				case "--download-content":
					downloadContent = true
				default:
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Argumento desconhecido para !run: `%s`", arg))
					return
				}
			}
			// Configura o logger com base na flag --verbose
			var discordLogger *slog.Logger
			if verbose {
				discordWriter := NewDiscordWriter(s, m.ChannelID)
				discordLogger = slog.New(slog.NewTextHandler(discordWriter, nil))
			}

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🚀 Iniciando fluxo completo para o alvo: `%s`...", runTarget))

			var wg sync.WaitGroup

			// Fluxo principal (Recon + Scan) sempre é executado
			wg.Add(1)
			go func() {
				defer wg.Done()
				if StartRunFunc != nil {
					loggerToUse := discordLogger
					if loggerToUse == nil {
						loggerToUse = slog.Default() // Usa o logger padrão (que vai para o console) se não for verbose
					}
					var presetsList []string
					if bbotPresets != "" {
						presetsList = strings.Split(bbotPresets, ",")
					}
					// A chamada para StartRunFunc foi corrigida para usar a variável correta.
					summary, files, err := StartRunFunc(context.Background(), target.GetRootDomain(runTarget), runTarget, reconSkipSteps, scanSkipSteps, scanOnlySteps, bbotModules, strings.Join(presetsList, ","), nucleiGroup, isAggressive, skipAnalysis, true, forceScan, downloadContent, loggerToUse)
					if err != nil {
						s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ O fluxo 'run' (recon+scan) para `%s` falhou: %v", runTarget, err))
					} else {
						SendSummaryAndFiles(s, m.ChannelID, summary, files)
					}
				} else {
					s.ChannelMessageSend(m.ChannelID, "Erro interno: A função 'run' não está configurada.")
				}
			}()

			// Fluxo de Infraestrutura (se a flag for passada)
			if withInfra {
				wg.Add(1)
				go func() {
					defer wg.Done()
					taskIdentifier := target.GetRootDomain(runTarget)
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("- Iniciando Varredura de Infraestrutura para `%s` em paralelo...", runTarget))
					loggerToUse := discordLogger
					if loggerToUse == nil {
						loggerToUse = slog.Default()
					}
					summary, files, err := StartInfraFunc(taskIdentifier, runTarget, nil, nil, []string{}, loggerToUse) // Passa nil para presets/modules
					if err != nil {
						s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Varredura de infra para `%s` falhou: %v", runTarget, err))
					} else {
						SendSummaryAndFiles(s, m.ChannelID, summary, files)
					}
				}()
			}

			// Fluxo de Análise Web (se a flag for passada)
			if withWeb {
				wg.Add(1)
				go func() {
					defer wg.Done()
					taskIdentifier := target.GetRootDomain(runTarget)
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("- Iniciando Análise Web para `https://%s` em paralelo...", runTarget))
					loggerToUse := discordLogger
					if loggerToUse == nil {
						loggerToUse = slog.Default()
					}
					summary, files, err := StartWebFunc(taskIdentifier, "https://"+runTarget, 2, false, "", nil, loggerToUse) // Profundidade padrão, não permite subdomínios
					if err != nil {
						s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Análise web para `%s` falhou: %v", runTarget, err))
					} else {
						SendSummaryAndFiles(s, m.ChannelID, summary, files)
					}
				}()
			}
		case "web":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!web <url> [-d depth] [-n task_name]`")
				return
			}

			var targetArg string
			depth := 2
			allowSubdomains := false
			var bbotPreset string // Adicionado para consistência
			var discordLogger *slog.Logger
			for i := 0; i < len(cmdArgs); i++ {
				arg := cmdArgs[i]
				switch arg {
				case "-d", "--depth":
					if i+1 < len(cmdArgs) {
						fmt.Sscanf(cmdArgs[i+1], "%d", &depth)
						i++
					}
				case "--allow-subdomains":
					allowSubdomains = true
				case "--verbose":
					if discordLogger == nil {
						discordWriter := NewDiscordWriter(s, m.ChannelID)
						discordLogger = slog.New(slog.NewTextHandler(discordWriter, nil))
					}
				case "--bbot-preset":
					if discordLogger == nil {
						discordWriter := NewDiscordWriter(s, m.ChannelID)
						discordLogger = slog.New(slog.NewTextHandler(discordWriter, nil))
					}
				default:
					if targetArg == "" {
						targetArg = arg
					}
				}
			}

			taskIdentifier := target.GetRootDomain(targetArg)

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🕸️ Iniciando rastreamento e análise web para `%s` (Profundidade: %d)...", targetArg, depth))
			loggerToUse := discordLogger
			if loggerToUse == nil {
				loggerToUse = slog.Default()
			}
			// Passa nil para o proxyManager, pois o comando !web não tem flags de proxy
			summary, files, err := StartWebFunc(taskIdentifier, targetArg, depth, allowSubdomains, bbotPreset, nil, loggerToUse)
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
			var discordLogger *slog.Logger
			for _, arg := range cmdArgs {
				if arg == "--verbose" {
					discordWriter := NewDiscordWriter(s, m.ChannelID)
					discordLogger = slog.New(slog.NewTextHandler(discordWriter, nil))
					break
				}
			}
			taskIdentifier := target.GetRootDomain(targetArg)

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🏗️ Iniciando varredura de infraestrutura para `%s`...", targetArg))
			loggerToUse := discordLogger
			if loggerToUse == nil {
				loggerToUse = slog.Default()
			}
			summary, files, err := StartInfraFunc(taskIdentifier, targetArg, nil, nil, []string{}, discordLogger)
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
			var discordLogger *slog.Logger
			for _, arg := range cmdArgs {
				if arg == "--verbose" {
					discordWriter := NewDiscordWriter(s, m.ChannelID)
					discordLogger = slog.New(slog.NewTextHandler(discordWriter, nil))
					break
				}
			}

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🔎 Iniciando varredura de API para a tarefa `%s`...", taskIdentifier))
			loggerToUse := discordLogger
			if loggerToUse == nil {
				loggerToUse = slog.Default()
			}
			summary, files, err := StartAPIFunc(taskIdentifier, []string{}, nil, nil, discordLogger)
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

		case "fullrun":
			if len(cmdArgs) < 1 {
				s.ChannelMessageSend(m.ChannelID, "Uso: `!fullrun <alvo> [flags...]`\nUse `!help` para ver as flags disponíveis.")
				return
			}

			// Variáveis para armazenar os valores das flags
			var (
				targetArg       string
				reconSkipSteps  []string
				scanSkipSteps   []string // Adicionado bbotPresets
				scanOnlySteps   []string
				infraSkipSteps  []string
				isAggressive    bool
				skipAnalysis    bool
				forceScan       bool
				bbotModules     string
				nucleiGroup     string
				bbotPresets     string // Nova flag
				downloadContent bool
				verbose         bool
				webDepth        = 2 // Profundidade padrão para o web crawl
			)

			targetArg = cmdArgs[0]

			// Analisa as flags a partir dos argumentos
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
				case "--infra-skip":
					if i+1 < len(cmdArgs) {
						infraSkipSteps = strings.Split(cmdArgs[i+1], ",")
						i++
					}
				case "--web-depth":
					if i+1 < len(cmdArgs) {
						fmt.Sscanf(cmdArgs[i+1], "%d", &webDepth)
						i++
					}
				case "--aggressive":
					isAggressive = true
				case "--skip-analysis":
					skipAnalysis = true
				case "--download-content":
					downloadContent = true
				case "--force-scan":
					forceScan = true
				case "--verbose":
					verbose = true
				case "--bbot-modules":
					if i+1 < len(cmdArgs) {
						bbotModules = cmdArgs[i+1]
						i++
					}
				case "--nuclei-group":
					if i+1 < len(cmdArgs) {
						nucleiGroup = cmdArgs[i+1]
						i++
					}
				case "--bbot-presets":
					if i+1 < len(cmdArgs) {
						bbotPresets = cmdArgs[i+1]
						i++
					}
				default:
					s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Argumento desconhecido para !fullrun: `%s`", arg))
					return
				}
			}

			// Configura o logger com base na flag --verbose
			var discordLogger *slog.Logger
			if verbose {
				discordWriter := NewDiscordWriter(s, m.ChannelID)
				discordLogger = slog.New(slog.NewTextHandler(discordWriter, nil))
			}

			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("🚀 Iniciando fluxo **COMPLETO** para o alvo: `%s` com configurações customizadas...", targetArg))

			var wg sync.WaitGroup
			wg.Add(3) // 1 para recon+scan, 1 para infra, 1 para web

			// Goroutine para Recon + Scan (agora usa as flags parseadas)
			go func() {
				defer wg.Done()
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("- Iniciando Recon & Scan para `%s`...", targetArg))
				if StartRunFunc != nil {
					// Passa as flags parseadas para a função de execução
					loggerToUse := discordLogger
					if loggerToUse == nil {
						loggerToUse = slog.Default()
					}
					// Declara as variáveis antes de usá-las na chamada da função.
					var summary string
					var files []string
					var err error
					summary, files, err = StartRunFunc(context.Background(), target.GetRootDomain(targetArg), targetArg, reconSkipSteps, scanSkipSteps, scanOnlySteps, bbotModules, bbotPresets, nucleiGroup, isAggressive, skipAnalysis, true, forceScan, downloadContent, loggerToUse)
					if err != nil {
						s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ O fluxo 'run' (recon+scan) para `%s` falhou: %v", targetArg, err))
					} else {
						SendSummaryAndFiles(s, m.ChannelID, summary, files)
					}
				}
			}()

			// Goroutine para Infra (agora usa as flags parseadas)
			go func() {
				defer wg.Done()
				taskIdentifier := target.GetRootDomain(targetArg)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("- Iniciando Varredura de Infraestrutura para `%s`...", targetArg))
				if StartInfraFunc != nil {
					loggerToUse := discordLogger
					if loggerToUse == nil {
						loggerToUse = slog.Default()
					}
					var presets []string
					if bbotPresets != "" {
						presets = strings.Split(bbotPresets, ",")
					}
					var modules []string
					if bbotModules != "" {
						modules = strings.Split(bbotModules, ",")
					}
					summary, files, err := StartInfraFunc(taskIdentifier, targetArg, infraSkipSteps, presets, modules, loggerToUse)
					if err != nil {
						s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("❌ Varredura de infra para `%s` falhou: %v", targetArg, err))
					} else {
						SendSummaryAndFiles(s, m.ChannelID, summary, files)
					}
				}
			}()

			// Goroutine para Web (agora usa a profundidade da flag)
			go func() {
				defer wg.Done()
				taskIdentifier := target.GetRootDomain(targetArg)
				s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("- Iniciando Análise Web para `https://%s` com profundidade %d...", targetArg, webDepth))
				loggerToUse := discordLogger
				if loggerToUse == nil {
					loggerToUse = slog.Default()
				}
				StartWebFunc(taskIdentifier, "https://"+targetArg, webDepth, false, "", nil, loggerToUse) // Subdomains not allowed by default in fullrun
			}()

		case "help":
			helpMsg := "Comandos disponíveis:\n" +
				"`!fullrun <target> [flags...]` - Executa recon, scan, infra e web em paralelo. (Equivalente ao `fullrun` da CLI)\n" +
				"`!exploit <module> <host>` - Tenta executar um módulo do Metasploit em um alvo.\n" +
				"`!run <target>` - Executa um fluxo completo de reconhecimento e varredura.\n" +
				"`!stop <task_name>` - Cancela uma tarefa em andamento (ex: `!stop example.com`).\n" +
				"`!infra <target>` - Inicia uma varredura de infraestrutura.\n" +
				"`!api <task_name>` - Inicia uma varredura de API baseada nos resultados de uma tarefa existente.\n" +
				"`!web <url>` - Rastreia e analisa um site específico. Flags: `-d <profundidade>`.\n" +
				"`!monitor <add|status|stop|start>` - Gerencia o monitoramento contínuo.\n" +
				"`!status` - Lista todas as tarefas com resultados existentes.\n" +
				"`!results <alvo> [--partial]` - Mostra o resumo e os arquivos de uma tarefa (mesmo que em andamento).\n" +
				"`!search <termo> [flags]` - Procura por um termo nos resultados.\n" +
				"  - Flags: `-t <alvo>` (para buscar apenas em um alvo), `-l` (listar arquivos), `-r` (usar Regex).\n" +
				"  - Exemplo: `!search \"api_key\" -t example.com -r`\n\n" +
				"**Flags para `!run` e `!fullrun`:**\n" +
				"  `--with-infra`: Adiciona a varredura de infraestrutura em paralelo.\n" +
				"  `--with-web`: Adiciona a análise web aprofundada em paralelo.\n" +
				"  `--recon-skip <etapas>`: Pula etapas do recon (ex: `webenum,fuzz`).\n" +
				"  `--scan-only <etapas>`: Executa apenas certas etapas do scan (ex: `nuclei`).\n" +
				"  `--bbot-modules <modulos>`: Define módulos específicos do bbot para o recon (ex: `recon/scans/light`).\n" +
				"  `--bbot-presets <presets>`: Define presets do bbot para o recon (ex: `web-basic,subdomain-enum`).\n" +
				"  `--nuclei-group <grupo>`: Define um grupo de templates do Nuclei para o scan (ex: `wordpress`).\n" +
				"  `--web-depth <num>`: Define a profundidade do crawl web (padrão: 2).\n" +
				"  `--download-content`: Habilita o download de conteúdo JS durante o recon.\n" +
				"  `--verbose`: Mostra os logs detalhados da execução em tempo real no Discord."
			s.ChannelMessageSend(m.ChannelID, helpMsg)
		default:
			s.ChannelMessageSend(m.ChannelID, fmt.Sprintf("Comando desconhecido: `%s`. Use `!help` para ver os comandos.", command))
		}
	}()
}

// isAuthorized verifica se o autor da mensagem tem permissão para executar comandos.
func isAuthorized(s *discordgo.Session, m *discordgo.MessageCreate) bool {
	securityConfig := config.Cfg.Engine.Discord.Security
	if !securityConfig.Enabled {
		return true // Bypass se a segurança estiver desabilitada
	}

	// Verifica se o usuário está na whitelist
	for _, id := range securityConfig.WhitelistUsers {
		if m.Author.ID == id {
			return true
		}
	}

	// Verifica se o usuário possui algum dos cargos permitidos
	if m.GuildID != "" && len(securityConfig.AllowedRoles) > 0 {
		member, err := s.GuildMember(m.GuildID, m.Author.ID)
		if err != nil {
			slog.Warn("Falha ao obter informações do membro para checar cargos", "user", m.Author.ID, "error", err)
			return false // Fail-safe: nega o acesso se não conseguir verificar os cargos
		}
		for _, roleID := range member.Roles {
			for _, allowedRoleID := range securityConfig.AllowedRoles {
				if roleID == allowedRoleID {
					return true
				}
			}
		}
	}

	return false // Nega por padrão
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
	switch strings.ToUpper(finding.Severity) {
	case "CRITICAL", "CRITICO":
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
				Title:       fmt.Sprintf("🚨 Nova Vulnerabilidade: %s", finding.Meta.Info.Name),
				Description: finding.Meta.Info.Description, // Agora NucleiInfo tem Description
				Color:       color,
				Fields: []types.EmbedField{
					{Name: "Alvo", Value: finding.Meta.Host, Inline: true},
					{Name: "Severidade", Value: strings.ToUpper(finding.Severity), Inline: true},
					{Name: "Template", Value: finding.Meta.TemplateID, Inline: false},
				},
				Footer: &types.EmbedFooter{Text: fmt.Sprintf("Monitorando: %s", target)},
			},
		},
	}

	payloadBytes, _ := json.Marshal(payload)
	http.Post(webhookURL, "application/json", bytes.NewBuffer(payloadBytes))
}

func StartBot() {
	var err error
	dg, err = discordgo.New("Bot " + config.Cfg.Engine.Discord.Token)
	if err != nil {
		slog.Error("error creating Discord session,", "error", err)
		return
	}

	slog.Info("Connecting to Discord and verifying bot token...")
	u, err := dg.User("@me")
	if err != nil {
		slog.Error("error obtaining account details,", "error", err)
		return
	}
	botID = u.ID

	// Adiciona o handler de mensagens
	dg.AddHandler(messageCreate)

	// Define as permissões (intents) que o bot precisa.
	// IntentsGuildMembers é uma intent privilegiada e precisa ser habilitada no Discord Developer Portal.
	// Se a verificação de cargos não for necessária, ela pode ser removida para evitar erros.
	dg.Identify.Intents = discordgo.IntentsGuildMessages
	dg.Identify.Intents = discordgo.IntentsGuildMessages | discordgo.IntentsGuildMembers

	// Abre a conexão
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
