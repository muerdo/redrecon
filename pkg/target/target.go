package target

import (
	"net"
	"net/url"
	"strings"

	"redrecon/pkg/utils"

	"golang.org/x/net/publicsuffix"
)

// GetRootDomain extrai o domínio raiz de um determinado host ou URL.
func GetRootDomain(target string) string {
	// Tenta analisar como URL primeiro
	parsedURL, err := url.Parse(target)
	if err == nil && parsedURL.Hostname() != "" {
		target = parsedURL.Hostname()
	}

	// Remove a porta, se houver
	host, _, err := net.SplitHostPort(target)
	if err == nil {
		target = host
	}

	// Usa publicsuffix para encontrar o domínio efetivo de nível superior + 1
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil {
		// Fallback para uma lógica mais simples se o publicsuffix falhar
		parts := strings.Split(target, ".")
		if len(parts) > 1 {
			return strings.Join(parts[len(parts)-2:], ".")
		}
		return target
	}
	return eTLDPlusOne
}

// GetCommonTargetFromInput analisa um arquivo de entrada e determina se todos os alvos compartilham um domínio raiz comum.
func GetCommonTargetFromInput(inputFile string) (string, bool) {
	lines, err := utils.ReadLines(inputFile)
	if err != nil || len(lines) == 0 {
		return "", false
	}

	firstRootDomain := GetRootDomain(lines[0])
	for _, line := range lines[1:] {
		if GetRootDomain(line) != firstRootDomain {
			return "", false // Encontrou um domínio diferente, não há um alvo comum
		}
	}
	return firstRootDomain, true
}