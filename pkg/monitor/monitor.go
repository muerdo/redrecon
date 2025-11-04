package monitor

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"redrecon/internal/config"
	"redrecon/pkg/discord"
	"redrecon/pkg/utils"
	"redrecon/pkg/types"
	"redrecon/pkg/tools"
)

// Start inicia o processo de monitoramento para uma lista de alvos.
func Start(targets []string, frequency time.Duration) {
	slog.Info("Starting monitoring mode", "targets", targets, "frequency", frequency.String())

	if !config.Cfg.Engine.Discord.Enabled || config.Cfg.Engine.Discord.WebhookURL == "" {
		slog.Error("Discord webhook is not enabled or configured. Monitoring notifications cannot be sent. Exiting.")
		return
	}

	ticker := time.NewTicker(frequency)
	defer ticker.Stop()

	// Run once immediately, then on every tick.
	for ; ; <-ticker.C {
		for _, target := range targets {
			slog.Info("Running monitoring scan for target", "target", target)
			runScanForTarget(target)
		}
		slog.Info("Monitoring cycle finished. Waiting for next tick.", "next_run_in", frequency.String())
	}
}

// runScanForTarget executa o fluxo de varredura para um único alvo.
func runScanForTarget(target string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute) // Timeout de 30 min por alvo
	defer cancel()

	sanitizedTarget := utils.SanitizeTargetForPath(target)
	resultsPath := filepath.Join("results", sanitizedTarget, "monitor")
	if err := os.MkdirAll(resultsPath, 0755); err != nil {
		slog.Error("Failed to create monitor directory", "path", resultsPath, "error", err)
		return
	}

	tempDir := filepath.Join(resultsPath, "tmp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		slog.Error("Failed to create temporary directory for monitor scan", "path", tempDir, "error", err)
		return
	}

	// 1. Descoberta de subdomínios
	subdomainsFile := filepath.Join(resultsPath, "subdomains.txt")
	subfinderOutput, err := tools.RunSubfinder(ctx, target, tempDir, slog.Default())
	if err != nil {
		slog.Error("Subfinder failed during monitoring", "target", target, "error", err)
		return
	}
	if err := os.WriteFile(subdomainsFile, []byte(subfinderOutput), 0644); err != nil {
		slog.Error("Subfinder failed during monitoring", "target", target, "error", err)
		return
	}
	if !utils.FileExistsAndIsNotEmpty(subdomainsFile) {
		slog.Info("Subfinder ran but found no subdomains for target, skipping further steps.", "target", target)
		return
	}

	// 2. Descoberta de hosts ativos
	liveHostsFile := filepath.Join(resultsPath, "live_hosts.txt")
	// O arquivo de tecnologia não é usado no monitor, mas é necessário para a assinatura da função.
	techOutputFile := filepath.Join(tempDir, "tech_monitor.json")

	// CORREÇÃO: Ajusta a chamada para corresponder à nova assinatura da função RunHttpx.
	err = tools.RunHttpx(ctx, subdomainsFile, techOutputFile, liveHostsFile, tempDir, true, "80,443,8080,8443", false, slog.Default())
	if err != nil {
		slog.Error("Httpx failed during monitoring", "target", target, "error", err)
		return
	}
	if !utils.FileExistsAndIsNotEmpty(liveHostsFile) {
		slog.Info("No live hosts found for target, skipping nuclei scan", "target", target)
		return
	}

	// 3. Varredura com Nuclei
	nucleiResultsFile := filepath.Join(resultsPath, "nuclei_results.json")
	templates := config.Cfg.Recon.Nuclei.MonitorTemplates
	if len(templates) == 0 {
		slog.Warn("No monitor templates configured for Nuclei. Skipping scan.", "target", target)
		return
	}
	slog.Info("Starting Nuclei scan for monitoring", "target", target)

	// Para o monitor, usamos o perfil padrão de evasão.
	err = tools.RunNuclei(ctx, liveHostsFile, nucleiResultsFile, tempDir, templates, config.Cfg.Engine.WAF.DefaultProfile, false, slog.Default())
	if err != nil {
		// Nuclei pode sair com erro mesmo que encontre algo, então continuamos
		slog.Warn("Nuclei scan finished with an error, proceeding with result analysis", "target", target, "error", err)
	}

	// 4. Analisar e notificar sobre novas vulnerabilidades
	checkForNewVulnerabilities(target, nucleiResultsFile, resultsPath)
}

// checkForNewVulnerabilities compara os resultados atuais com os já reportados.
func checkForNewVulnerabilities(target, currentResultsFile, resultsPath string) {
	reportedFindingsFile := filepath.Join(resultsPath, "reported_findings.json")

	// Carregar vulnerabilidades já reportadas
	reportedFindings := loadReportedFindings(reportedFindingsFile)

	// Ler os resultados da varredura atual
	file, err := os.Open(currentResultsFile)
	if err != nil {
		slog.Error("Could not open nuclei results file", "file", currentResultsFile, "error", err)
		return
	}
	defer file.Close()

	newFindings := false
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var finding types.NucleiFinding
		if err := json.Unmarshal(scanner.Bytes(), &finding); err != nil {
			continue
		}

		// Criar um ID único para a vulnerabilidade (template + host + matcher)
		findingID := fmt.Sprintf("%s|%s|%s", finding.TemplateID, finding.Host, finding.MatcherName)

		if _, exists := reportedFindings[findingID]; !exists {
			// Nova vulnerabilidade encontrada!
			newFindings = true
			slog.Info("New vulnerability found!", "target", target, "template", finding.TemplateID, "host", finding.Host)
			discord.SendVulnerabilityNotification(target, finding)
			reportedFindings[findingID] = true
		}
	}

	if newFindings {
		// Salvar a lista atualizada de vulnerabilidades reportadas
		saveReportedFindings(reportedFindingsFile, reportedFindings)
	} else {
		slog.Info("No new vulnerabilities found for target", "target", target)
	}
}

func loadReportedFindings(filePath string) map[string]bool {
	findings := make(map[string]bool)
	data, err := os.ReadFile(filePath)
	if err != nil {
		// Se o arquivo não existe, é a primeira execução. Retorna um mapa vazio.
		return findings
	}

	if err := json.Unmarshal(data, &findings); err != nil {
		slog.Error("Failed to unmarshal reported findings", "file", filePath, "error", err)
		// Retorna um mapa vazio para evitar perda de dados em caso de corrupção
		return make(map[string]bool)
	}
	return findings
}

func saveReportedFindings(filePath string, findings map[string]bool) {
	data, err := json.MarshalIndent(findings, "", "  ")
	if err != nil {
		slog.Error("Failed to marshal reported findings for saving", "file", filePath, "error", err)
		return
	}

	if err := os.WriteFile(filePath, data, 0644); err != nil {
		slog.Error("Failed to write reported findings file", "file", filePath, "error", err)
	}
}
