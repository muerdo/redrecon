package tools

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

// RunRustScan runs rustscan to find open ports.
// It returns a list of open ports as a slice of strings.
func RunRustScan(ctx context.Context, target string, logger *slog.Logger) ([]string, error) {
	cfg := config.Cfg.Tools.RustScan
	if !cfg.Enabled {
		logger.Info("RustScan is disabled in configuration.")
		return nil, nil
	}

	path := cfg.Path
	if path == "" {
		path = "rustscan" // Default to PATH
	}

	// rustscan -a <target> -g <ports> -- <nmap_args>
	// We only want the ports, so we use -g (grepable) or parse stdout.
	// RustScan format: Open 22,80,443
	// We'll use the default output and parse "Open <ports>"

	args := []string{"-a", target, "--scripts", "None"} // --scripts None to avoid nmap invocation by rustscan itself if possible, though rustscan usually chains nmap.
	// Actually, rustscan by default runs nmap. To prevent this and just get ports, we can use -n (no config) or just parse the output before it runs nmap?
	// RustScan 2.0+ runs nmap by default. To stop it, we can pass -- -sV (or nothing?)
	// A better way is to use -q (quiet) or just capture the output.
	// Let's use -b (batch size) and --timeout from config.

	args = append(args, cfg.ExtraArgs...)

	// To prevent rustscan from running nmap, we can pass a dummy command or just let it run and ignore nmap output?
	// RustScan docs say: "RustScan [flags] -- [nmap-flags]"
	// If we don't want nmap, we might not be able to fully disable it easily without -g?
	// Let's try to use -g which prints ports to stdout and exits? No, -g is for grepable?
	// Actually, `rustscan -a target --ulimit 5000` prints "Open 127.0.0.1:80" etc.

	// Let's stick to parsing the standard output which usually contains "Open 80,443" line.
	// And we can pass "-- -sn" to nmap to make it fast/noop if we can't disable it?
	// Or just let it run, we only care about the "Open ..." line.

	logger.Info("Running RustScan", "target", target, "args", args)

	// We need to capture stdout
	output, err := utils.ExecuteCommand(ctx, logger, path, args...)
	if err != nil {
		return nil, fmt.Errorf("rustscan failed: %w", err)
	}

	return parseRustScanOutput(output)
}

func parseRustScanOutput(output string) ([]string, error) {
	// Example output:
	// Open 127.0.0.1:80
	// Open 127.0.0.1:443
	// OR
	// 80/tcp open http
	//
	// RustScan usually outputs: "Open 22,80,443" in some versions or "127.0.0.1 -> [22, 80, 443]"
	// Let's handle the common "Open <port>,<port>" format or "Open <ip>:<port>"

	var ports []string

	// Regex for "Open 22,80,443"
	// But wait, newer rustscan might be different.
	// Let's look for "Open \d+(,\d+)*"

	// Pattern 1: Open 22,80,443
	// reComma := regexp.MustCompile(`Open \d+(?:,\d+)*`) // Unused
	// Pattern 2: 80/tcp
	// Let's try to be robust.

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Open") {
			// Try to find ports
			// Example: Open 1.2.3.4:80
			if strings.Contains(line, ":") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					port := strings.TrimSpace(parts[len(parts)-1])
					ports = append(ports, port)
				}
			} else {
				// Example: Open 22,80,443
				parts := strings.Split(line, " ")
				if len(parts) >= 2 {
					portStr := parts[1] // 22,80,443
					pList := strings.Split(portStr, ",")
					ports = append(ports, pList...)
				}
			}
		}
	}

	return utils.UniqueStrings(ports), nil
}
