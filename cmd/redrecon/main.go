package main

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"redrecon/cmd/redrecon/cmd"
)

func checkHostOS() error {
	if runtime.GOOS != "linux" {
		msg := fmt.Sprintf("unsupported operating system: %s. This program is optimized for Parrot or Kali Linux", runtime.GOOS)
		return fmt.Errorf(msg)
	}

	content, err := os.ReadFile("/etc/os-release")
	if err != nil {
		slog.Error("could not check Linux distribution", "error", err)
		return err
	}

	lowerContent := strings.ToLower(string(content))
	if !strings.Contains(lowerContent, "id=kali") && !strings.Contains(lowerContent, "id=parrot") {
		return fmt.Errorf("unsupported Linux distribution. Please run on Parrot or Kali Linux")
	}
	return nil
}

func main() {
	// A verificação do SO pode ser mantida se for um requisito estrito.
	// if err := checkHostOS(); err != nil {
	// 	fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	// 	os.Exit(1)
	// }

	// Register all commands
	// Commands are self-registered in their respective init functions

	cmd.Execute()
}
