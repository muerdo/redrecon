package infra

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"redrecon/pkg/utils"
	"redrecon/pkg/tools"
)

type infraState struct {
	ctx         context.Context
	target      string
	resultsPath string
	tempDir     string
	logger      *slog.Logger

	nmapFile         string
	enum4linuxNGFile string
	cmeSmbFile       string
	cmeSshFile       string
	sipScanFile      string
	dnsEnumFile      string
	cloudEnumFile    string
	sslScanFile      string
	rpcScanFile      string
	snmpScanFile     string
}

type infraStep func(state *infraState) error

func StartInfra(taskIdentifier, target string, skipSteps []string, logger *slog.Logger) (string, []string, error) {
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
		ctx:         context.Background(),
		target:      target,
		resultsPath: resultsPath,
		tempDir:     tempDir,
		logger:      logger,

		nmapFile:         filepath.Join(resultsPath, "nmap_full_scan.xml"),
		enum4linuxNGFile: filepath.Join(resultsPath, "enum4linux_ng_scan.txt"),
		cmeSmbFile:       filepath.Join(resultsPath, "crackmapexec_smb.txt"),
		cmeSshFile:       filepath.Join(resultsPath, "crackmapexec_ssh.txt"),
		sipScanFile:      filepath.Join(resultsPath, "sip_scan.txt"),
		dnsEnumFile:      filepath.Join(resultsPath, "dns_enum.txt"),
		cloudEnumFile:    filepath.Join(resultsPath, "cloud_enum.json"),
		sslScanFile:      filepath.Join(resultsPath, "ssl_scan.txt"),
		rpcScanFile:      filepath.Join(resultsPath, "nmap_rpc_scan.txt"),
		snmpScanFile:     filepath.Join(resultsPath, "nmap_snmp_scan.txt"),
	}

	skipSet := make(map[string]struct{})
	for _, step := range skipSteps {
		skipSet[strings.ToLower(step)] = struct{}{}
	}

	workflow := map[string]infraStep{
		"nmap":         stepRunNmap,
		"enum4linux":   stepRunEnum4linuxNG,
		"crackmapexec": stepRunCrackMapExec,
		"sipscan":      stepRunSipScan,
		"dnsenum":      stepRunDnsEnum,
		"cloudenum":    stepRunCloudEnum,
		"sslscan":      stepRunSslScan,
		"rpcscan":      stepRunNmapRpcScan,
		"snmpscan":     stepRunNmapSnmpScan,
	}

	executionOrder := []string{"dnsenum", "nmap", "cloudenum", "sslscan", "rpcscan", "snmpscan", "enum4linux", "crackmapexec", "sipscan"}

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

func stepRunNmap(state *infraState) error {
	state.logger.Info("Executing full nmap scan. This may take a while...", "target", state.target)

	err := tools.RunNmap(state.ctx, state.target, state.nmapFile, state.logger,
		"-p-", "-sV", "-sC", "-T4", "-oX", state.nmapFile)

	if err != nil {
		return fmt.Errorf("nmap execution failed: %w", err)
	}

	state.logger.Info("Nmap scan completed", "output_file", state.nmapFile)
	return nil
}

func stepRunCrackMapExec(state *infraState) error {
	state.logger.Info("--- Starting: Service Enumeration (CrackMapExec) ---")

	state.logger.Info("Running CrackMapExec for SMB enumeration")
	smbOutput, err := tools.RunCrackMapExec(state.ctx, "smb", state.target, state.logger)
	if err != nil {
		state.logger.Warn("CrackMapExec (SMB) failed, but continuing.", "error", err)
	} else if smbOutput != "" {
		if err := os.WriteFile(state.cmeSmbFile, []byte(smbOutput), 0644); err != nil {
			state.logger.Error("Failed to write CrackMapExec SMB results", "error", err)
		}
	}

	state.logger.Info("Running CrackMapExec for SSH enumeration")
	sshOutput, err := tools.RunCrackMapExec(state.ctx, "ssh", state.target, state.logger)
	if err != nil {
		state.logger.Warn("CrackMapExec (SSH) failed, but continuing.", "error", err)
	} else if sshOutput != "" {
		if err := os.WriteFile(state.cmeSshFile, []byte(sshOutput), 0644); err != nil {
			state.logger.Error("Failed to write CrackMapExec SSH results", "error", err)
		}
	}

	state.logger.Info("CrackMapExec enumeration completed.")
	return nil
}

func stepRunSipScan(state *infraState) error {
	state.logger.Info("--- Starting: SIP/VoIP Scanning (svmap) ---")
	return tools.RunSipScan(state.ctx, state.target, state.sipScanFile, state.logger)
}

func stepRunDnsEnum(state *infraState) error {
	state.logger.Info("--- Starting: DNS Enumeration (dnsx) ---")
	return tools.RunDnsxInfra(state.ctx, state.target, state.dnsEnumFile, state.logger)
}

func stepRunCloudEnum(state *infraState) error {
	state.logger.Info("--- Starting: Cloud Service Enumeration (cloudenum) ---")
	return tools.RunCloudEnum(state.ctx, state.target, state.cloudEnumFile, state.logger)
}

func stepRunSslScan(state *infraState) error {
	state.logger.Info("--- Starting: SSL/TLS Configuration Scan (sslscan) ---")
	return tools.RunSslScan(state.ctx, state.target, state.sslScanFile, state.logger)
}

func stepRunEnum4linuxNG(state *infraState) error {
	state.logger.Info("--- Starting: SMB Enumeration (enum4linux-ng) ---")
	err := tools.RunEnum4linuxNG(state.ctx, state.target, state.enum4linuxNGFile, state.logger)
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
	err := tools.RunNmap(state.ctx, state.target, state.snmpScanFile, state.logger,
		"-sU", "-p", "161", "--script=snmp-info,snmp-enum-shares", "-oN", state.snmpScanFile)
	if err != nil {
		state.logger.Warn("Nmap SNMP scan failed, but continuing.", "error", err)
	}
	return nil
}

func generateInfraSummary(state *infraState) (string, []string) {
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("✅ **Infra Scan Summary for: %s**\n\n", state.target))

	files := []string{}

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