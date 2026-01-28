package tools

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	
	"redrecon/internal/config"
)

// RunDnsxInfra runs dnsx for infrastructure scanning.
func RunDnsxInfra(ctx context.Context, target, outputFile string, logger *slog.Logger) error {
	// Adiciona flags para consultar tipos de registro específicos (-a, -aaaa, etc.)
	// Versões recentes do dnsx exigem uma wordlist com -d. A abordagem correta para um
	// único alvo é passá-lo via stdin para a flag -l (lista).
	toolPath := config.GetToolPath("dnsx")
	dnsxConfig := config.Cfg.Recon.Dnsx
	if !dnsxConfig.Enabled {
		logger.Info("dnsx is disabled in config, skipping.")
		return nil
	}

	args := []string{"-l", "-", "-o", outputFile, "-silent"}
	if len(dnsxConfig.InfraArgs) > 0 {
		args = append(args, dnsxConfig.InfraArgs...)
	} else {
		// Fallback para argumentos padrão se não estiverem no config
		args = append(args, "-a", "-aaaa", "-cname", "-ns", "-mx", "-txt")
	}
	args = append(args, dnsxConfig.ExtraArgs...)

	// Prepara o stdin para o comando
	input := bytes.NewBufferString(target)
	_, err := ExecuteCommandWithStdin(ctx, logger, input, toolPath, args...)
	return err
}

// RunDnsxForDC runs dnsx to find Domain Controllers via SRV records.
func RunDnsxForDC(ctx context.Context, domain, outputFile string, logger *slog.Logger) error {
	toolPath := config.GetToolPath("dnsx")
	dnsxConfig := config.Cfg.Recon.Dnsx
	if !dnsxConfig.Enabled {
		logger.Info("dnsx is disabled in config, skipping DC discovery.")
		return nil
	}

	// O alvo para a busca de DC é o registro SRV _ldap._tcp no domínio.
	targetSRV := fmt.Sprintf("_ldap._tcp.%s", domain)

	args := []string{
		"-l", "-", // Ler da entrada padrão
		"-o", outputFile,
		"-silent",
		"-srv", // Especifica uma consulta SRV
	}
	args = append(args, dnsxConfig.ExtraArgs...)

	input := bytes.NewBufferString(targetSRV)
	_, err := ExecuteCommandWithStdin(ctx, logger, input, toolPath, args...)
	return err
}