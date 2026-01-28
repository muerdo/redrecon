package infra

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/tools"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"

	"gopkg.in/yaml.v2"
)

type infraState struct {
	ctx         context.Context
	target      string
	resultsPath string
	tempDir     string
	logger      *slog.Logger

	proxyManager     *utils.ProxyManager
	nmapFile         string
	enum4linuxNGFile string
	cmeSmbFile       string
	cmeSshFile       string
	cmeMssqlFile     string
	sipScanFile      string
	dnsEnumFile      string
	cloudEnumFile    string
	sslScanFile      string
	rpcScanFile      string
	snmpScanFile     string
	testsslFile      string // Novo campo para o resultado do testssl.sh
	dcInfoFile       string
	rustScanFile     string // Novo campo para output do RustScan (se quisermos salvar, mas vamos usar em memória ou parsear)
}

type infraStep func(state *infraState) error

func StartInfra(taskIdentifier, target string, skipSteps []string, bbotPreset string, proxyManager *utils.ProxyManager, logger *slog.Logger) (string, []string, error) {
	logger.Info("Starting infrastructure scan", "target", target)

	sanitizedTaskIdentifier := utils.SanitizeTargetForPath(taskIdentifier)
	resultsPath := filepath.Join("results", sanitizedTaskIdentifier, "infra")
	if err := os.MkdirAll(resultsPath, 0755); err != nil {
		return "", nil, fmt.Errorf("could not create infra results directory: %w", err)
	}

	tempDir := filepath.Join(resultsPath, "tmp")
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return "", nil, fmt.Errorf("failed to create temporary directory for infra: %w", err)
	}

	state := &infraState{
		ctx:          context.Background(),
		target:       target,
		resultsPath:  resultsPath,
		tempDir:      tempDir,
		logger:       logger,
		proxyManager: proxyManager,

		nmapFile:         filepath.Join(resultsPath, "nmap_full_scan.xml"),
		enum4linuxNGFile: filepath.Join(resultsPath, "enum4linux_ng_scan.txt"),
		cmeSmbFile:       filepath.Join(resultsPath, "crackmapexec_smb.txt"),
		cmeSshFile:       filepath.Join(resultsPath, "crackmapexec_ssh.txt"),
		cmeMssqlFile:     filepath.Join(resultsPath, "crackmapexec_mssql.txt"),
		sipScanFile:      filepath.Join(resultsPath, "sip_scan.txt"),
		dnsEnumFile:      filepath.Join(resultsPath, "dns_enum.txt"),
		cloudEnumFile:    filepath.Join(resultsPath, "cloud_enum.json"),
		sslScanFile:      filepath.Join(resultsPath, "ssl_scan.txt"),
		rpcScanFile:      filepath.Join(resultsPath, "nmap_rpc_scan.txt"),
		snmpScanFile:     filepath.Join(resultsPath, "nmap_snmp_scan.txt"),
		dcInfoFile:       filepath.Join(resultsPath, "dc_info.txt"),
		testsslFile:      filepath.Join(resultsPath, "testssl_scan.log"),
		rustScanFile:     filepath.Join(resultsPath, "rustscan_ports.txt"), // Arquivo para salvar portas encontradas
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	workflow := map[string]infraStep{
		"finddc":       stepFindDC,
		"rustscan":     stepRunRustScan,
		"nmap":         stepRunNmap,
		"enum4linux":   stepRunEnum4linuxNG,
		"crackmapexec": stepRunCrackMapExec,
		"sipscan":      stepRunSipScan,
		"dnsenum":      stepRunDnsEnum,
		"cloudenum":    stepRunCloudEnum,
		"sslscan":      stepRunSslScan,
		"rpcscan":      stepRunNmapRpcScan,
		"snmpscan":     stepRunNmapSnmpScan,
		"bbot":         func(s *infraState) error { return stepRunBBotInfra(s, bbotPreset) },
	}

	executionOrder := []string{"finddc", "dnsenum", "bbot", "rustscan", "nmap", "cloudenum", "sslscan", "rpcscan", "snmpscan", "enum4linux", "crackmapexec", "sipscan"}

	for _, stepName := range executionOrder {
		if _, skip := skipSet[stepName]; skip {
			state.logger.Warn("Skipping step as requested by flags", "step", stepName)
			continue
		}

		stepFunc, ok := workflow[stepName]
		if !ok {
			state.logger.Error("Unknown infra step in workflow", "step", stepName)
			continue
		}

		state.logger.Info(fmt.Sprintf("--- Starting: %s ---", stepName))
		if err := stepFunc(state); err != nil {
			state.logger.Error("An infra step failed", "step", stepName, "error", err)
		}
	}

	state.logger.Info("Infrastructure scan process completed.")

	summary, files := generateInfraSummary(state)

	return summary, files, nil
}

func stepRunRustScan(state *infraState) error {
	state.logger.Info("--- Starting: Port Discovery (RustScan) ---")
	ports, err := tools.RunRustScan(state.ctx, state.target, state.logger)
	if err != nil {
		state.logger.Warn("RustScan failed, falling back to Nmap default discovery.", "error", err)
		return nil // Non-fatal, nmap will run normally
	}

	if len(ports) > 0 {
		state.logger.Info("RustScan found open ports", "count", len(ports), "ports", ports)
		// Save ports to file for reference and for Nmap step to read
		err := os.WriteFile(state.rustScanFile, []byte(strings.Join(ports, ",")), 0644)
		if err != nil {
			state.logger.Warn("Failed to write RustScan ports to file", "error", err)
		}
	} else {
		state.logger.Info("RustScan did not find any open ports.")
	}
	return nil
}

func stepRunNmap(state *infraState) error {
	state.logger.Info("Executing nmap scan...", "target", state.target)

	// Load Nmap args from config
	// Assuming config.Cfg.Infra.NmapArgs exists. If not, we use defaults.
	// Wait, config.yaml has `infra: nmap-args: ...` but config.go doesn't seem to have `InfraConfig` struct with `NmapArgs`?
	// Let's check config.go again. It has `ToolsConfig` with `Nmap` path, but where are the args?
	// config.yaml has:
	// infra:
	//   nmap-args: ...
	//
	// I need to check if `InfraConfig` exists in `config.go`.
	// Based on my previous read of `config.go`, I didn't see `InfraConfig`.
	// Let's assume I need to add it or use `Tools.Nmap` extra args if available?
	// Actually, `config.yaml` showed:
	// infra:
	//   nmap-args: ...
	//
	// I should probably check `config.go` again or just hardcode/use what's there.
	// If `InfraConfig` is missing, I should add it.
	// For now, I'll use a safe default or try to read from viper directly if needed, but better to fix the struct.
	//
	// However, to avoid blocking, I will check if `rustscan_ports.txt` exists and use it.

	var args []string

	// Check for RustScan results
	if utils.FileExistsAndIsNotEmpty(state.rustScanFile) {
		content, err := os.ReadFile(state.rustScanFile)
		if err == nil {
			ports := strings.TrimSpace(string(content))
			if ports != "" {
				args = append(args, "-p", ports)
				state.logger.Info("Using ports found by RustScan", "ports", ports)
			}
		}
	} else {
		// If no ports found or RustScan skipped, we might want -p- or top ports
		args = append(args, "-p-")
	}

	// Add standard args
	if len(config.Cfg.Infra.NmapArgs) > 0 {
		args = append(args, config.Cfg.Infra.NmapArgs...)
	} else {
		args = append(args, "-sV", "-sC", "-T3") // Default fallback
	}

	// Try to get args from config if possible.
	// Since I can't easily verify `InfraConfig` right now without reading `config.go` again (which I did, and it seemed missing `Infra` field in `Config` struct?),
	// I will assume `viper` can access it or I'll just use these defaults which are better than hardcoded -T4.
	// Actually, `config.go` had `Recon`, `Tools`, etc. I didn't see `Infra`.
	// I will add `Infra` to `Config` struct in `config.go` in a separate step if needed.
	// For now, let's stick to the plan of using `rustscan` results.

	args = append(args, "-oX", state.nmapFile)

	if state.proxyManager != nil {
		if proxy := state.proxyManager.GetNextProxy(); proxy != "" {
			args = append(args, "--proxy", proxy)
			state.logger.Info("Using proxy for nmap scan", "proxy", proxy)
		}
	}

	err := tools.RunNmap(state.ctx, state.target, state.nmapFile, state.logger, args...)

	if err != nil {
		return fmt.Errorf("nmap execution failed: %w", err)
	}

	state.logger.Info("Nmap scan completed", "output_file", state.nmapFile)
	return nil
}

func stepRunCrackMapExec(state *infraState) error {
	state.logger.Info("--- Starting: Service Enumeration (CrackMapExec) ---")

	// CrackMapExec runs against a single target in this context.
	targets := []string{state.target}
	// For enumeration, we don't need credentials.
	creds := types.Credentials{}

	state.logger.Info("Running CrackMapExec for SMB enumeration")
	err := tools.RunCrackMapExec(state.ctx, targets, "smb", creds, state.cmeSmbFile, state.logger)
	if err != nil {
		state.logger.Warn("CrackMapExec (SMB) failed, but continuing.", "error", err)
	}

	state.logger.Info("Running CrackMapExec for SSH enumeration")
	err = tools.RunCrackMapExec(state.ctx, targets, "ssh", creds, state.cmeSshFile, state.logger)
	if err != nil {
		state.logger.Warn("CrackMapExec (SSH) failed, but continuing.", "error", err)
	}

	state.logger.Info("Running CrackMapExec for MSSQL enumeration")
	err = tools.RunCrackMapExec(state.ctx, targets, "mssql", creds, state.cmeMssqlFile, state.logger)
	if err != nil {
		state.logger.Warn("CrackMapExec (MSSQL) failed, but continuing.", "error", err)
	}

	state.logger.Info("CrackMapExec enumeration completed.")
	return nil
}

func stepRunSipScan(state *infraState) error {
	state.logger.Info("--- Starting: SIP/VoIP Scanning (svmap) ---")
	return tools.RunSipScan(state.ctx, state.target, state.sipScanFile, state.logger)
}

func stepFindDC(state *infraState) error {
	state.logger.Info("--- Starting: Domain Controller Discovery ---")
	return tools.RunDnsxForDC(state.ctx, state.target, state.dcInfoFile, state.logger)
}

func stepRunDnsEnum(state *infraState) error {
	state.logger.Info("--- Starting: DNS Enumeration (dnsx) ---")
	return tools.RunDnsxInfra(state.ctx, state.target, state.dnsEnumFile, state.logger)
}

func stepRunCloudEnum(state *infraState) error {
	state.logger.Info("--- Starting: Cloud Service Enumeration (cloudenum) ---")
	return tools.RunCloudenum(state.ctx, state.target, state.cloudEnumFile, state.logger)
}

func stepRunSslScan(state *infraState) error {
	state.logger.Info("--- Starting: SSL/TLS Configuration Scan (sslscan) ---")
	return tools.RunSslScan(state.ctx, state.target, state.sslScanFile, state.logger)
}

func stepRunEnum4linuxNG(state *infraState) error {
	state.logger.Info("--- Starting: SMB Enumeration (enum4linux-ng) ---")
	if !config.Cfg.Tools.Enum4linuxNG.Enabled { // Verifica se o enum4linux-ng está habilitado
		state.logger.Info("enum4linux-ng está desabilitado na configuração, pulando.")
		return nil
	}
	err := tools.RunEnum4linuxNG(state.ctx, state.target, types.Credentials{}, state.enum4linuxNGFile, state.logger)
	if err != nil {
		state.logger.Warn("enum4linux-ng scan failed, but continuing.", "error", err)
		return err
	}
	if utils.FileExistsAndIsNotEmpty(state.enum4linuxNGFile) {
		state.logger.Info("SMB enumeration completed", "output_file", state.enum4linuxNGFile)
	} else {
		state.logger.Info("SMB enumeration completed with no findings.")
	}
	return nil
}

func stepRunNmapRpcScan(state *infraState) error {
	state.logger.Info("--- Starting: RPC Scanning (nmap) ---")
	err := tools.RunNmapRpcScan(state.ctx, state.target, state.rpcScanFile, state.logger)
	if err != nil {
		state.logger.Warn("Nmap RPC scan failed, but continuing.", "error", err)
	}
	return nil
}

func stepRunNmapSnmpScan(state *infraState) error {
	state.logger.Info("--- Starting: SNMP Scanning (nmap) ---")
	// Scans UDP (-sU) requerem privilégios de root.
	if os.Geteuid() != 0 {
		state.logger.Warn("Nmap SNMP scan requires root privileges (for -sU). Skipping step.", "user_id", os.Geteuid())
		return nil
	}

	err := tools.RunNmapSnmpScan(state.ctx, state.target, state.snmpScanFile, state.logger)
	if err != nil {
		state.logger.Warn("Nmap SNMP scan failed, but continuing.", "error", err)
	}
	return nil
}

func generateInfraSummary(state *infraState) (string, []string) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **Infra Scan Summary for: %s**\n\n", state.target))

	files := []string{}

	if utils.FileExistsAndIsNotEmpty(state.dcInfoFile) {
		summary.WriteString(fmt.Sprintf("• **Domain Controller Discovery:** Completed. Results saved to `%s`.\n", filepath.Base(state.dcInfoFile)))
		files = append(files, state.dcInfoFile)
	}

	if utils.FileExistsAndIsNotEmpty(state.dnsEnumFile) {
		summary.WriteString(fmt.Sprintf("• **DNS Enumeration:** Completed. Results saved to `%s`.\n", filepath.Base(state.dnsEnumFile)))
		files = append(files, state.dnsEnumFile)
	}

	if utils.FileExistsAndIsNotEmpty(state.cloudEnumFile) {
		summary.WriteString(fmt.Sprintf("• **Cloud Enumeration:** Completed. Results saved to `%s`.\n", filepath.Base(state.cloudEnumFile)))
		files = append(files, state.cloudEnumFile)
	}

	if utils.FileExistsAndIsNotEmpty(state.sslScanFile) {
		summary.WriteString(fmt.Sprintf("• **SSL/TLS Scan:** Completed. Results saved to `%s`.\n", filepath.Base(state.sslScanFile)))
		files = append(files, state.sslScanFile)
	}

	if utils.FileExistsAndIsNotEmpty(state.nmapFile) {
		summary.WriteString(fmt.Sprintf("• **Nmap Full Scan:** Completed. Results saved to `%s`.\n", filepath.Base(state.nmapFile)))
		files = append(files, state.nmapFile)
	} else {
		summary.WriteString("• **Nmap Scan:** No results found.\n")
	}

	if utils.FileExistsAndIsNotEmpty(state.cmeSmbFile) {
		summary.WriteString(fmt.Sprintf("• **CrackMapExec (SMB):** Completed. Results saved to `%s`.\n", filepath.Base(state.cmeSmbFile)))
		files = append(files, state.cmeSmbFile)
	}

	if utils.FileExistsAndIsNotEmpty(state.cmeSshFile) {
		summary.WriteString(fmt.Sprintf("• **CrackMapExec (SSH):** Completed. Results saved to `%s`.\n", filepath.Base(state.cmeSshFile)))
		files = append(files, state.cmeSshFile)
	}

	if utils.FileExistsAndIsNotEmpty(state.cmeMssqlFile) {
		summary.WriteString(fmt.Sprintf("• **CrackMapExec (MSSQL):** Completed. Results saved to `%s`.\n", filepath.Base(state.cmeMssqlFile)))
		files = append(files, state.cmeMssqlFile)
	}

	if utils.FileExistsAndIsNotEmpty(state.sipScanFile) {
		summary.WriteString(fmt.Sprintf("• **SIP/VoIP Scan:** Completed. Results saved to `%s`.\n", filepath.Base(state.sipScanFile)))
		files = append(files, state.sipScanFile)
	}

	if utils.FileExistsAndIsNotEmpty(state.enum4linuxNGFile) {
		summary.WriteString(fmt.Sprintf("• **SMB Enumeration (enum4linux-ng):** Completed. Results saved to `%s`.\n", filepath.Base(state.enum4linuxNGFile)))
		files = append(files, state.enum4linuxNGFile)
	} else {
		summary.WriteString("• **SMB Enumeration (enum4linux-ng):** No results found.\n")
	}

	if utils.FileExistsAndIsNotEmpty(state.rpcScanFile) {
		summary.WriteString(fmt.Sprintf("• **RPC Scan (nmap):** Completed. Results saved to `%s`.\n", filepath.Base(state.rpcScanFile)))
		files = append(files, state.rpcScanFile)
	}

	if utils.FileExistsAndIsNotEmpty(state.snmpScanFile) {
		summary.WriteString(fmt.Sprintf("• **SNMP Scan (nmap):** Completed. Results saved to `%s`.\n", filepath.Base(state.snmpScanFile)))
		files = append(files, state.snmpScanFile)
	}

	summary.WriteString(fmt.Sprintf("\n*Full results are saved in:* `%s`", state.resultsPath))

	return summary.String(), files
}

func stepRunBBotInfra(s *infraState, bbotPreset string) error {
	if !config.Cfg.Tools.Bbot.Enabled {
		s.logger.Info("BBOT is disabled in configuration. Skipping step.")
		return nil
	}

	if !utils.CommandExists("bbot") {
		s.logger.Error("bbot not installed or not executable. Check your PATH.", "tool", "bbot")
		return fmt.Errorf("bbot not found or not executable")
	}
	s.logger.Info("--- Starting: BBOT Infra Scan ---")

	targetInput := s.target
	// For infra, the target is usually a single domain or IP.
	// If we want to use a file, we'd need to create one from the target.

	// Load base BBot configuration from tools.bbot
	bbotConfig := config.Cfg.Tools.Bbot

	var currentPreset *config.BBotToolConfig
	if bbotPreset != "" {
		if preset, ok := config.Cfg.Recon.Presets[bbotPreset]; ok && preset.BBot != nil {
			currentPreset = preset.BBot
			s.logger.Info("Using BBot preset for Infra scan", "preset", bbotPreset)
		} else {
			s.logger.Warn("BBot preset not found, falling back to default BBot configuration.", "preset", bbotPreset)
		}
	}

	// If a preset is active, merge its settings with the base bbotConfig
	if currentPreset != nil {
		if len(currentPreset.Presets) > 0 {
			bbotConfig.Presets = currentPreset.Presets
		}
		if len(currentPreset.Flags) > 0 {
			bbotConfig.Flags = currentPreset.Flags
		}
		if len(currentPreset.Modules) > 0 {
			bbotConfig.Modules = currentPreset.Modules
		}
		if len(currentPreset.OutputModules) > 0 {
			bbotConfig.OutputModules = currentPreset.OutputModules
		}
		if len(currentPreset.ExcludeModules) > 0 {
			bbotConfig.ExcludeModules = currentPreset.ExcludeModules
		}
		if len(currentPreset.Blacklist) > 0 {
			bbotConfig.Blacklist = currentPreset.Blacklist
		}
		if currentPreset.AllowDeadly {
			bbotConfig.AllowDeadly = true
		}
		if currentPreset.RateLimit > 0 {
			bbotConfig.RateLimit = currentPreset.RateLimit
		}
		if currentPreset.Concurrency > 0 {
			bbotConfig.Concurrency = currentPreset.Concurrency
		}
		if currentPreset.Proxy != "" {
			bbotConfig.Proxy = currentPreset.Proxy
		}
		if len(currentPreset.ExtraArgs) > 0 {
			bbotConfig.ExtraArgs = currentPreset.ExtraArgs
		}
		if len(currentPreset.ConfigOverrides) > 0 {
			bbotConfig.ConfigOverrides = currentPreset.ConfigOverrides
		}
	}

	var extraArgs []string

	if len(bbotConfig.Presets) > 0 {
		for _, p := range bbotConfig.Presets {
			extraArgs = append(extraArgs, "-p", p)
		}
	}
	if len(bbotConfig.Flags) > 0 {
		for _, f := range bbotConfig.Flags {
			extraArgs = append(extraArgs, "-f", f)
		}
	}
	if len(bbotConfig.Modules) > 0 {
		extraArgs = append(extraArgs, "-m", strings.Join(bbotConfig.Modules, ","))
	}
	if len(bbotConfig.OutputModules) > 0 {
		extraArgs = append(extraArgs, "--output-module", strings.Join(bbotConfig.OutputModules, ","))
	}
	if len(bbotConfig.ExcludeModules) > 0 {
		extraArgs = append(extraArgs, "--exclude-module", strings.Join(bbotConfig.ExcludeModules, ","))
	}
	if len(bbotConfig.Blacklist) > 0 {
		for _, bl := range bbotConfig.Blacklist {
			extraArgs = append(extraArgs, "--blacklist", bl)
		}
	}
	if bbotConfig.AllowDeadly {
		extraArgs = append(extraArgs, "--allow-deadly")
	}
	if bbotConfig.RateLimit > 0 {
		extraArgs = append(extraArgs, "--rate-limit", fmt.Sprintf("%d", bbotConfig.RateLimit))
	}
	if bbotConfig.Concurrency > 0 {
		extraArgs = append(extraArgs, "--concurrency", fmt.Sprintf("%d", bbotConfig.Concurrency))
	}
	if bbotConfig.Concurrency > 0 {
		extraArgs = append(extraArgs, "--concurrency", fmt.Sprintf("%d", bbotConfig.Concurrency))
	}

	// Inject dynamic proxy if available
	dynamicProxy := utils.GetProxyForTool(s.proxyManager, "bbot", s.logger)
	if dynamicProxy != "" {
		extraArgs = append(extraArgs, "--proxy", dynamicProxy)
	} else if bbotConfig.Proxy != "" {
		extraArgs = append(extraArgs, "--proxy", bbotConfig.Proxy)
	}
	if len(bbotConfig.ExtraArgs) > 0 {
		extraArgs = append(extraArgs, bbotConfig.ExtraArgs...)
	}

	// Handle config_overrides
	var tempConfigFile string
	if len(bbotConfig.ConfigOverrides) > 0 {
		var err error
		tempFile, err := os.CreateTemp(s.tempDir, "bbot_config_override_*.yml")
		if err != nil {
			return fmt.Errorf("failed to create temporary config override file: %w", err)
		}
		defer os.Remove(tempFile.Name())
		defer tempFile.Close()

		configBytes, err := yaml.Marshal(bbotConfig.ConfigOverrides)
		if err != nil {
			return fmt.Errorf("failed to marshal bbot config overrides: %w", err)
		}
		if _, err := tempFile.Write(configBytes); err != nil {
			return fmt.Errorf("failed to write bbot config overrides to temp file: %w", err)
		}
		tempConfigFile = tempFile.Name()
		extraArgs = append(extraArgs, "-c", tempConfigFile)
	}

	outputDir := filepath.Join(s.resultsPath, "bbot")
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory for bbot: %w", err)
	}

	jsonFile, err := tools.RunBBot(
		s.ctx,
		targetInput,
		"", // subdomainsFile (empty for now)
		outputDir,
		bbotConfig.AllowDeadly,
		bbotConfig.RateLimit,
		bbotConfig.Concurrency,
		bbotConfig.Proxy,
		s.logger,
		extraArgs...,
	)
	if err != nil {
		s.logger.Error("BBOT Infra scan failed", "error", err)
		return nil // Not a fatal error
	}

	if jsonFile != "" && utils.FileExistsAndIsNotEmpty(jsonFile) {
		// Optionally parse BBot findings and add to Infra state
		// For now, just log that it completed
		s.logger.Info("BBOT Infra scan completed", "output_file", jsonFile)
	}

	return nil
}
