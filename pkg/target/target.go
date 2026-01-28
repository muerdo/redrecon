package target

import (
	"net"
	"net/url"
	"strings"

	"redrecon/pkg/utils"

	"golang.org/x/net/publicsuffix"
)

// GetRootDomain extrai o domínio raiz de um determinado host ou URL.
// Em contextos CTF/local, preserva subdomínios como staging.example.com
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

	// NOVO: Detectar e preservar domínios CTF/locais
	if isLocalOrCTFDomain(target) {
		return target // Preserva staging.ctf.com, dev.htb, etc
	}

	// Para domínios públicos, usa publicsuffix
	eTLDPlusOne, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil {
		// Fallback: retorna o domínio original
		return target
	}
	return eTLDPlusOne
}

// isLocalOrCTFDomain detecta se um domínio é local, CTF ou tem subdomínio importante
func isLocalOrCTFDomain(domain string) bool {
	// Lista de TLDs comuns em CTFs e ambientes locais
	ctfTLDs := []string{".htb", ".thm", ".ctf", ".local", ".lab", ".box"}
	for _, tld := range ctfTLDs {
		if strings.HasSuffix(domain, tld) {
			return true
		}
	}

	// Detecta se é um endereço IP
	if net.ParseIP(domain) != nil {
		return true
	}

	// Detecta subdomínios importantes (staging, dev, test, api, admin, etc)
	importantPrefixes := []string{"staging.", "dev.", "test.", "api.", "admin.", "portal.", "app.", "beta.", "demo."}
	for _, prefix := range importantPrefixes {
		if strings.HasPrefix(domain, prefix) {
			return true
		}
	}

	return false
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
