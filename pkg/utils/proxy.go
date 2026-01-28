package utils

import (
	"bufio"
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"redrecon/internal/config"
)

// GetGlobalProxy retorna o endereço do proxy a ser usado, seguindo uma ordem de prioridade.
// 1. Proxy Global (engine.proxy)
// 2. Proxy de Evasão (evasion.tor_proxy_address)
func GetGlobalProxy() string {
	// Prioridade 1: Proxy Global
	if config.Cfg != nil && config.Cfg.Engine.Proxy != "" {
		return config.Cfg.Engine.Proxy
	}

	// Prioridade 2: Proxy de Evasão (Tor)
	if config.Cfg != nil && config.Cfg.Evasion.Enabled && config.Cfg.Evasion.UseTor && config.Cfg.Evasion.TorProxyAddress != "" {
		return config.Cfg.Evasion.TorProxyAddress
	}

	return ""
}

// LoadProxiesFromFile loads proxies from a file (one proxy per line in IP:PORT format)
func LoadProxiesFromFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open proxy file %s: %w", filePath, err)
	}
	defer file.Close()

	var proxies []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		proxies = append(proxies, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading proxy file: %w", err)
	}

	return proxies, nil
}

// GetLiveProxyList loads the live proxy list from 3proxy's exported file
func GetLiveProxyList() ([]string, error) {
	proxyFile := "/tmp/3proxy-live-proxies.txt"

	// Check if file exists
	if _, err := os.Stat(proxyFile); os.IsNotExist(err) {
		return nil, fmt.Errorf("proxy list file not found: %s (is 3proxy-rotator service running?)", proxyFile)
	}

	proxies, err := LoadProxiesFromFile(proxyFile)
	if err != nil {
		return nil, err
	}

	if len(proxies) == 0 {
		return nil, fmt.Errorf("no proxies found in %s", proxyFile)
	}

	return proxies, nil
}

// LogProxyUsage logs the proxy being used for audit trail
func LogProxyUsage(logger *slog.Logger, toolName, proxyURL string) {
	if logger != nil {
		logger.Info("Using proxy for tool",
			"tool", toolName,
			"proxy", proxyURL,
			"timestamp", time.Now().Format(time.RFC3339),
		)
	}

	// Also write to audit file for permanent tracking
	auditFile := "/tmp/proxy-audit.log"
	f, err := os.OpenFile(auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		auditLine := fmt.Sprintf("%s | %s | %s\n",
			time.Now().Format(time.RFC3339),
			toolName,
			proxyURL,
		)
		f.WriteString(auditLine)
	}
}

// GetProxyForTool gets the next proxy from ProxyManager and logs it for audit
// Returns empty string if proxyManager is nil or has no proxies
func GetProxyForTool(proxyManager *ProxyManager, toolName string, logger *slog.Logger) string {
	if proxyManager == nil {
		return ""
	}

	proxy := proxyManager.GetNextProxy()
	if proxy != "" {
		LogProxyUsage(logger, toolName, proxy)
	}

	return proxy
}

// WaitForProxies blocks until the proxy list file is available and not empty, or timeout is reached.
// If allowFallback is true, returns nil after timeout to allow execution without proxies.
func WaitForProxies(logger *slog.Logger, timeout time.Duration, allowFallback bool) error {
	proxyFile := "/tmp/3proxy-live-proxies.txt"

	op := func() error {
		if FileExistsAndIsNotEmpty(proxyFile) {
			// Double check if we can actually load them
			proxies, err := LoadProxiesFromFile(proxyFile)
			if err == nil && len(proxies) > 0 {
				if logger != nil {
					logger.Info("Proxy list found and loaded.", "count", len(proxies))
				}
				return nil
			}
		}

		if logger != nil {
			logger.Info("Waiting for 3proxy to generate live proxy list...", "file", proxyFile)
		} else {
			fmt.Printf("Waiting for 3proxy to generate live proxy list at %s...\n", proxyFile)
		}

		return fmt.Errorf("proxies not ready")
	}

	retryConfig := CTFRetryConfig() // Use fast retries
	retryConfig.MaxElapsedTime = timeout
	retryConfig.MaxInterval = 5 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := RetryWithBackoff(ctx, op, retryConfig); err != nil {
		if allowFallback {
			if logger != nil {
				logger.Warn("Proxy list not available after timeout, continuing without proxies", "timeout", timeout)
			}
			return nil
		}
		return fmt.Errorf("timeout waiting for proxy list after %v: %w", timeout, err)
	}

	return nil
}

// LoadProxiesFromFlagsOrDefault loads proxies from flags or falls back to the default live file.
// It creates a consistent behavior across all commands:
// 1. If flags usage is detected (list or file), it uses them.
// 2. If no flags, it checks /tmp/3proxy-live-proxies.txt and uses it if available.
// 3. If neither, it returns nil (direct connection).
func LoadProxiesFromFlagsOrDefault(logger *slog.Logger, flagProxies []string, flagProxyFile string) ([]string, error) {
	// 1. Explicit flags have highest priority
	if len(flagProxies) > 0 {
		return flagProxies, nil
	}

	if flagProxyFile != "" {
		loadedProxies, err := LoadProxiesFromFile(flagProxyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load proxies from flag file %s: %w", flagProxyFile, err)
		}
		if len(loadedProxies) == 0 {
			if logger != nil {
				logger.Warn("Provided proxy file is empty", "file", flagProxyFile)
			}
			return nil, nil
		}
		return loadedProxies, nil
	}

	// 2. Fallback to default live file
	liveProxyFile := "/tmp/3proxy-live-proxies.txt"
	if FileExistsAndIsNotEmpty(liveProxyFile) {
		loadedProxies, err := LoadProxiesFromFile(liveProxyFile)
		if err == nil {
			if logger != nil {
				logger.Info("Using live proxies from default file", "file", liveProxyFile, "count", len(loadedProxies))
			}
			return loadedProxies, nil
		}
		// Log warning but don't fail, as this is an implicit fallback
		if logger != nil {
			logger.Warn("Failed to read default proxy file", "file", liveProxyFile, "error", err)
		}
	}

	// 3. No proxies found
	return nil, nil
}
