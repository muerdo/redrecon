package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"redrecon/internal/config"
	"redrecon/pkg/recon"
	"redrecon/pkg/scan"
	"redrecon/pkg/tools"
	"redrecon/pkg/utils"
)

var (
	// Callbacks para desacoplar o monitor do Discord
	OnNewAssetsResponse  func(target string, newSubdomains []string)
	OnVulnerabilityFound func(summary string, files []string)
)

var (
	state      MonitorState
	stateFile  string
	stateMutex sync.Mutex
	stopFunc   context.CancelFunc
)

type MonitorState struct {
	Targets   []string  `json:"targets"`
	LastCycle time.Time `json:"last_cycle"`
	IsRunning bool      `json:"is_running"`
}

var runCounter = 0

// Start inicia o processo de monitoramento contínuo para uma lista de alvos.
func Start(targets []string, frequency time.Duration) {
	if !config.Cfg.Monitor.Enabled {
		slog.Warn("O modo de monitoramento está desabilitado na configuração.")
		return
	}

	// Inicializa o estado
	stateFile = filepath.Join(config.GetTempDir(), "monitor_state.json")
	loadState()
	if len(targets) > 0 {
		AddTargets(targets)
	}

	if state.IsRunning {
		slog.Warn("O monitor já está em execução.")
		return
	}

	// Verifica se a escalada automática com Metasploit está habilitada e testa a conexão.
	if config.Cfg.Metasploit.Enabled && config.Cfg.Metasploit.AutoEscalate {
		slog.Info("Auto-escalate com Metasploit está habilitado. Testando conexão com MSGRPC...")
		msf, err := tools.NewMetasploit(context.Background(), slog.Default())
		if err != nil {
			slog.Error("Falha ao conectar com o Metasploit. O monitoramento continuará, mas a escalada automática não funcionará.", "error", err)
		} else {
			slog.Info("✅ Conexão com Metasploit bem-sucedida.")
			msf.Close()
		}
	}

	slog.Info("Iniciando modo de monitoramento contínuo.", "targets", targets, "frequency", frequency)

	var ctx context.Context
	ctx, stopFunc = context.WithCancel(context.Background())
	state.IsRunning = true
	saveState()

	// Executa uma vez imediatamente e depois inicia o ticker
	ticker := time.NewTicker(frequency)
	defer ticker.Stop()

	for range ticker.C {
		slog.Info("Iniciando novo ciclo de monitoramento agendado.")
		var wg sync.WaitGroup
		for _, target := range state.Targets {
			wg.Add(1)
			go func(t string) {
				defer wg.Done()
				runMonitoringCycle(ctx, t)
			}(target)
		}
		wg.Wait()
		state.LastCycle = time.Now()
		saveState()
		slog.Info("Ciclo de monitoramento concluído.")
	}
}

func Stop() error {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	if !state.IsRunning {
		return fmt.Errorf("o monitor não está em execução")
	}
	if stopFunc != nil {
		stopFunc()
		state.IsRunning = false
		slog.Info("Processo de monitoramento foi parado.")
		return saveState()
	}
	return fmt.Errorf("função de parada não encontrada")
}

// runMonitoringCycle executa um ciclo completo de monitoramento para um único alvo.
func runMonitoringCycle(ctx context.Context, target string) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil)).With("target", target)
	logger.Info("Iniciando ciclo de monitoramento para o alvo.")

	// Seleciona o grupo de módulos do bbot para esta execução (rotação)
	bbotGroups := config.Cfg.Monitor.BbotRotation
	var bbotPresets []string
	if len(bbotGroups) > 0 {
		groupIndex := runCounter % len(bbotGroups)
		bbotPresets = bbotGroups[groupIndex]
		logger.Info("Executando com o grupo de presets do bbot.", "group_index", groupIndex, "presets", bbotPresets)
	}
	runCounter++

	// Caminhos para os arquivos de estado
	taskIdentifier := utils.SanitizeTargetForPath(target)
	reconPath := filepath.Join("results", taskIdentifier, "recon")
	currentSubdomainsFile := filepath.Join(reconPath, "subdomains.txt")
	previousSubdomainsFile := filepath.Join(reconPath, "subdomains.previous.txt")

	// 1. Faz backup dos resultados anteriores
	if utils.FileExistsAndIsNotEmpty(currentSubdomainsFile) {
		if err := os.Rename(currentSubdomainsFile, previousSubdomainsFile); err != nil {
			logger.Error("Falha ao fazer backup do arquivo de subdomínios anterior.", "error", err)
		}
	}

	// 2. Executa a fase de reconhecimento
	_, _, _, err := recon.StartRecon(ctx, target, target, []string{target}, nil, nil, nil, nil, false, true, false, false, false, false, "", "", nil, nil, "", "", "", logger, false)
	if err != nil {
		logger.Error("A fase de reconhecimento do ciclo de monitoramento falhou.", "error", err)
		return
	}

	// 3. Compara os resultados para encontrar novos subdomínios
	newSubdomains, err := utils.DiffFiles(previousSubdomainsFile, currentSubdomainsFile)
	if err != nil {
		logger.Error("Falha ao comparar arquivos de subdomínios para encontrar novos ativos.", "error", err)
		return
	}

	if len(newSubdomains) == 0 {
		logger.Info("Nenhum novo subdomínio encontrado neste ciclo.")
		return
	}

	logger.Info("Novos subdomínios encontrados!", "count", len(newSubdomains))

	// 4. Prepara para escanear apenas os novos subdomínios
	newTargetsFile, err := os.CreateTemp(reconPath, "new_targets_*.txt")
	if err != nil {
		logger.Error("Falha ao criar arquivo temporário para novos alvos.", "error", err)
		return
	}
	defer os.Remove(newTargetsFile.Name())
	if _, err := newTargetsFile.WriteString(strings.Join(newSubdomains, "\n")); err != nil {
		logger.Error("Falha ao escrever novos alvos no arquivo temporário.", "error", err)
		return
	}
	newTargetsFile.Close()

	// 5. Executa o scan de "low-hanging fruits" nos novos subdomínios
	lfrGroup := config.Cfg.Monitor.NucleiLFRGroup
	if lfrGroup != "" {
		logger.Info("Iniciando varredura de 'low-hanging fruits' nos novos subdomínios.", "nuclei_group", lfrGroup)

		// Usamos um identificador de tarefa específico para o scan de monitoramento
		scanTaskID := fmt.Sprintf("%s-monitor-%s", taskIdentifier, time.Now().Format("20060102-150405"))

		summary, files, err := scan.StartScan(ctx, scanTaskID, newTargetsFile.Name(), nil, []string{"nuclei"}, lfrGroup, "", "", "", false, false, nil, "", "", "", logger)
		if err != nil {
			logger.Error("A varredura de 'low-hanging fruits' falhou.", "error", err)
		} else {
			logger.Info("Varredura de 'low-hanging fruits' concluída.")
			if config.Cfg.Monitor.NotifyOnNew {
				// Chama o callback em vez de a função direta do Discord
				if OnVulnerabilityFound != nil {
					OnVulnerabilityFound(summary, files)
				}
			}
		}
	}

	// Notificação para o Discord sobre os novos subdomínios
	if config.Cfg.Monitor.NotifyOnNew {
		// Chama o callback em vez de a função direta do Discord
		if OnNewAssetsResponse != nil {
			OnNewAssetsResponse(target, newSubdomains)
		}
	}
}

func AddTargets(targetsToAdd []string) {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	existingTargets := make(map[string]struct{})
	for _, t := range state.Targets {
		existingTargets[t] = struct{}{}
	}

	for _, t := range targetsToAdd {
		if _, exists := existingTargets[t]; !exists {
			state.Targets = append(state.Targets, t)
			slog.Info("Alvo adicionado ao monitoramento.", "target", t)
		}
	}
	saveState()
}

func RemoveTargets(targetsToRemove []string) []string {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	var removedTargets []string
	targetsToRemoveSet := make(map[string]struct{})
	for _, t := range targetsToRemove {
		targetsToRemoveSet[t] = struct{}{}
	}

	var newTargets []string
	for _, t := range state.Targets {
		if _, found := targetsToRemoveSet[t]; found {
			// Este alvo deve ser removido
			slog.Info("Alvo removido do monitoramento.", "target", t)
			removedTargets = append(removedTargets, t)
		} else {
			// Mantém este alvo
			newTargets = append(newTargets, t)
		}
	}
	state.Targets = newTargets
	saveState()
	return removedTargets
}

func GetStatus() string {
	stateMutex.Lock()
	defer stateMutex.Unlock()

	var status strings.Builder
	status.WriteString(fmt.Sprintf("**Status do Monitoramento**\n"))
	status.WriteString(fmt.Sprintf("- **Em Execução:** `%t`\n", state.IsRunning))
	status.WriteString(fmt.Sprintf("- **Último Ciclo:** `%s`\n", state.LastCycle.Format(time.RFC1123)))
	status.WriteString(fmt.Sprintf("- **Alvos Monitorados (%d):**\n", len(state.Targets)))
	for _, t := range state.Targets {
		status.WriteString(fmt.Sprintf("  - `%s`\n", t))
	}
	return status.String()
}

func loadState() {
	if !utils.FileExistsAndIsNotEmpty(stateFile) {
		state = MonitorState{Targets: []string{}}
		return
	}
	data, err := os.ReadFile(stateFile)
	if err != nil {
		slog.Error("Falha ao ler o arquivo de estado do monitor.", "error", err)
		state = MonitorState{Targets: []string{}}
		return
	}
	if err := json.Unmarshal(data, &state); err != nil {
		slog.Error("Falha ao decodificar o estado do monitor.", "error", err)
		state = MonitorState{Targets: []string{}}
	}
}

func saveState() error {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("falha ao codificar o estado do monitor: %w", err)
	}
	return os.WriteFile(stateFile, data, 0644)
}
