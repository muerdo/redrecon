package tools

import (
	"context"
	"fmt"
	"log/slog"

	"redrecon/internal/config"
)

// RunNmapSnmpScan executa o Nmap com scripts para enumeração SNMP.
func RunNmapSnmpScan(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	toolPath := config.GetToolPath("nmap")
	if toolPath == "" {
		return fmt.Errorf("nmap disabled or not found")
	}

	logger.Info("Executing Nmap SNMP scan", "target", target)
	// -sU para UDP scan, -p 161 para a porta SNMP, --script para os scripts de enumeração.
	err := RunNmap(ctx, target, outputFile, logger,
		"-sU", "-p", "161", "--script=snmp-info,snmp-enum-shares", "-oN", outputFile)

	return err
}