package infra

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

type infraState struct {
	ctx             context.Context
	target          string
	resultsPath     string
	subdomainsFile  string
	ipsFile         string
	ipsOnlyFile     string // Arquivo contendo apenas os IPs para o Nmap
	nmapFile        string
	nucleiInfraFile string
}

type infraStep func(state *infraState) error

func StartInfraScan(target string, skipSteps []string) error {
	slog.Info("Starting infrastructure scan process", "target", target)

	sanitizedTarget := sanitizeTargetForPath(target)
	resultsPath := filepath.Join("results", sanitizedTarget, "infra")
	slog.Info("Creating output directory", "path", resultsPath)

	if err := os.MkdirAll(resultsPath, 0755); err != nil {
		slog.Error("Failed to create directory", "path", resultsPath, "error", err)
		return fmt.Errorf("could not create directory %s: %w", resultsPath, err)
	}

	state := &infraState{
		ctx:             context.Background(),
		target:          target,
		resultsPath:     resultsPath,
		subdomainsFile:  filepath.Join(resultsPath, "subdomains.txt"),
		ipsFile:         filepath.Join(resultsPath, "resolved_ips.txt"),
		ipsOnlyFile:     filepath.Join(resultsPath, "ips_only.txt"),
		nmapFile:        filepath.Join(resultsPath, "nmap_scan.txt"),
		nucleiInfraFile: filepath.Join(resultsPath, "nuclei_infra_scan.txt"),
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	workflow := map[string]infraStep{
		"subfinder": stepRunSubfinder,
		"dnsx":      stepRunDnsx,
		"nmap":      stepRunNmap,
		"nuclei":    stepRunNuclei,
	}

	executionOrder := []string{"subfinder", "dnsx", "nmap", "nuclei"}

	for _, stepName := range executionOrder {
		if _, shouldSkip := skipSet[stepName]; shouldSkip {
			slog.Warn("Skipping infra step as requested", "step", stepName)
			continue
		}

		stepFunc := workflow[stepName]
		if err := stepFunc(state); err != nil {
			slog.Error("An infrastructure scan step failed", "step", stepName, "error", err)
		}
	}

	slog.Info("Infrastructure scan process completed.")
	return nil
}

func stepRunSubfinder(state *infraState) error {
	slog.Info("--- [Infra] Starting: Passive Subdomain Enumeration (subfinder) ---")
	cmd := exec.CommandContext(state.ctx, "subfinder", "-d", state.target, "-o", state.subdomainsFile, "-silent")
	if err := runCommand(cmd, "subfinder"); err != nil {
		return err
	}
	slog.Info("[Infra] Subfinder completed", "output_file", state.subdomainsFile)
	return nil
}

func stepRunDnsx(state *infraState) error {
	slog.Info("--- [Infra] Starting: IP Address Resolution (dnsx) ---")
	if !fileExistsAndIsNotEmpty(state.subdomainsFile) {
		slog.Warn("[Infra] Subdomains file is empty, skipping dnsx.", "file", state.subdomainsFile)
		return nil
	}
	cmd := exec.CommandContext(state.ctx, "dnsx", "-l", state.subdomainsFile, "-a", "-resp", "-o", state.ipsFile, "-silent")
	if err := runCommand(cmd, "dnsx"); err != nil {
		return err
	}
	slog.Info("[Infra] Dnsx completed", "output_file", state.ipsFile)
	return nil
}

func stepRunNmap(state *infraState) error {
	slog.Info("--- [Infra] Starting: Port Scanning (nmap) ---")
	if !fileExistsAndIsNotEmpty(state.ipsFile) {
		slog.Warn("[Infra] IPs file is empty, skipping nmap.", "file", state.ipsFile)
		return nil
	}

	err := extractIPs(state.ipsFile, state.ipsOnlyFile)
	if err != nil {
		return fmt.Errorf("failed to extract IPs for nmap: %w", err)
	}

	if !fileExistsAndIsNotEmpty(state.ipsOnlyFile) {
		slog.Warn("[Infra] No IPs were extracted, skipping nmap.", "file", state.ipsOnlyFile)
		return nil
	}

	cmd := exec.CommandContext(state.ctx, "nmap",
		"-iL", state.ipsOnlyFile,
		"-oN", state.nmapFile,
		"-sV",
		"-T4",
		"--top-ports", "1000",
		"--open",
	)
	if err := runCommand(cmd, "nmap"); err != nil {
		return err
	}
	slog.Info("[Infra] Nmap scan completed", "output_file", state.nmapFile)
	return nil
}

func stepRunNuclei(state *infraState) error {
	slog.Info("--- [Infra] Starting: Service Vulnerability Scanning (nuclei) ---")
	if !fileExistsAndIsNotEmpty(state.ipsFile) {
		slog.Warn("[Infra] IPs file is empty, skipping nuclei.", "file", state.ipsFile)
		return nil
	}
	cmd := exec.CommandContext(state.ctx, "nuclei",
		"-l", state.ipsFile,
		"-o", state.nucleiInfraFile,
		"-t", "network/",
		"-silent",
	)
	if err := runCommand(cmd, "nuclei"); err != nil {
		return err
	}
	slog.Info("[Infra] Nuclei scan on services completed", "output_file", state.nucleiInfraFile)
	return nil
}

func sanitizeTargetForPath(target string) string {
	replacer := strings.NewReplacer("http://", "", "https://", "", ":", "_", "/", "_", "?", "_", "&", "_", "=", "_")
	return replacer.Replace(target)
}

func fileExistsAndIsNotEmpty(path string) bool {
	stat, err := os.Stat(path)
	return !os.IsNotExist(err) && stat.Size() > 0
}

func runCommand(cmd *exec.Cmd, toolName string) error {
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	slog.Info("Executing command", "tool", toolName, "args", cmd.Args)
	err := cmd.Run()
	if err != nil {
		slog.Error("Command failed", "tool", toolName, "error", err, "stderr", stderr.String())
		return fmt.Errorf("%s execution failed: %w\nStderr: %s", toolName, err, stderr.String())
	}
	return nil
}

func extractIPs(inputFile, outputFile string) error {
	inFile, err := os.Open(inputFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	outFile, err := os.Create(outputFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	uniqueIPs := make(map[string]struct{})
	writer := bufio.NewWriter(outFile)
	scanner := bufio.NewScanner(inFile)
	ipRegex := regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

	for scanner.Scan() {
		line := scanner.Text()
		matches := ipRegex.FindAllString(line, -1)
		for _, ip := range matches {
			uniqueIPs[ip] = struct{}{}
		}
	}

	for ip := range uniqueIPs {
		_, _ = writer.WriteString(ip + "\n")
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	return writer.Flush()
}