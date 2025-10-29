package target

import (
	"bufio"
	"encoding/xml"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/joeguo/tldextract"
)

// Structs para fazer o unmarshal da saída XML do Nmap.
// Apenas os campos necessários para extrair alvos são definidos.
type NmapRun struct {
	Hosts []Host `xml:"host"`
}

type Host struct {
	Addresses []Address `xml:"address"`
	Hostnames Hostnames `xml:"hostnames"`
}

type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type Hostnames struct {
	Hostname []Hostname `xml:"hostname"`
}

type Hostname struct {
	Name string `xml:"name,attr"`
}

var (
	// Regex para encontrar domínios e IPs em texto.
	domainRegex = regexp.MustCompile(`([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.)+[a-zA-Z]{2,}`)
	ipRegex     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
)

var tldExtractor, _ = tldextract.New("tld.cache", true)

// IsTargetFile verifica se o caminho fornecido é um arquivo existente.
func IsTargetFile(target string) bool {
	info, err := os.Stat(target)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

// IsTargetDirectory verifica se o caminho fornecido é um diretório existente.
func IsTargetDirectory(target string) bool {
	info, err := os.Stat(target)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

// ParseTargetFile lê um único arquivo e extrai alvos normalizados.
func ParseTargetFile(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open target file %s: %w", filePath, err)
	}
	defer file.Close()

	var targets []string
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".json":
		targets = extractTargetsFromJSON(file)
	case ".xml":
		targets = extractTargetsFromXML(file)
	default: // Trata .txt e outros formatos como texto plano
		targets = extractTargetsFromText(file)
	}

	return normalizeTargets(targets), nil
}

// ParseTargetDirectory varre um diretório, lê todos os arquivos e extrai alvos.
func ParseTargetDirectory(dirPath string) ([]string, error) {
	allTargets := make(map[string]struct{})

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileTargets, err := ParseTargetFile(path)
			if err != nil {
				// Loga o erro mas continua para outros arquivos
				fmt.Printf("Warning: could not parse file %s: %v\n", path, err)
				return nil
			}
			for _, t := range fileTargets {
				allTargets[t] = struct{}{}
			}
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", dirPath, err)
	}

	var result []string
	for t := range allTargets {
		result = append(result, t)
	}

	return result, nil
}

// extractTargetsFromText lê um reader de texto e extrai domínios/IPs.
func extractTargetsFromText(reader io.Reader) []string {
	var targets []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		targets = append(targets, domainRegex.FindAllString(line, -1)...)
		targets = append(targets, ipRegex.FindAllString(line, -1)...)
	}
	return targets
}

// extractTargetsFromJSON lê um reader JSON e extrai strings que parecem alvos.
func extractTargetsFromJSON(reader io.Reader) []string {
	var data interface{}
	if err := json.NewDecoder(reader).Decode(&data); err != nil {
		return nil
	}

	var targets []string
	var findStrings func(interface{})
	findStrings = func(v interface{}) {
		switch val := v.(type) {
		case string:
			// Verifica se a string é um domínio ou IP válido
			if len(domainRegex.FindString(val)) > 0 || net.ParseIP(val) != nil {
				targets = append(targets, val)
			}
		case []interface{}:
			for _, item := range val {
				findStrings(item)
			}
		case map[string]interface{}:
			for _, item := range val {
				findStrings(item)
			}
		}
	}

	findStrings(data)
	return targets
}

// extractTargetsFromXML lê um reader XML (saída do Nmap) e extrai alvos.
func extractTargetsFromXML(reader io.Reader) []string {
	var nmapRun NmapRun
	if err := xml.NewDecoder(reader).Decode(&nmapRun); err != nil {
		// Se não for um XML do Nmap, tenta extrair como texto plano.
		// Isso torna a função mais robusta para arquivos XML genéricos.
		if seeker, ok := reader.(io.ReadSeeker); ok {
			seeker.Seek(0, io.SeekStart)
			return extractTargetsFromText(seeker)
		}
		return nil
	}

	var targets []string
	for _, host := range nmapRun.Hosts {
		// Adiciona nomes de host se existirem
		for _, hostname := range host.Hostnames.Hostname {
			if hostname.Name != "" {
				targets = append(targets, hostname.Name)
			}
		}
		// Adiciona endereços IP (ignora MAC addresses)
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				targets = append(targets, addr.Addr)
			}
		}
	}
	return targets
}

// normalizeTargets limpa uma lista de strings, extraindo o domínio/IP principal.
func normalizeTargets(targets []string) []string {
	normalized := make(map[string]struct{})
	// A extração de alvos já foi feita pelas funções extractTargetsFrom*.
	// Esta função agora apenas limpa e normaliza os alvos encontrados.
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// Adiciona "http://" se não houver esquema para url.Parse funcionar corretamente
		// e extrair o hostname corretamente, mesmo que tenha uma porta.
		if !strings.HasPrefix(t, "http://") && !strings.HasPrefix(t, "https://") {
			t = "http://" + t
		}

		u, err := url.Parse(t)
		if err == nil && u.Hostname() != "" {
			normalized[u.Hostname()] = struct{}{}
		}
	}

	var result []string
	for t := range normalized {
		result = append(result, t)
	}
	return result
}

// GetRootDomain extrai o domínio raiz de um determinado hostname.
// Por exemplo, "sub.example.co.uk" se torna "example.co.uk".
// Se for um IP, retorna o próprio IP.
func GetRootDomain(hostname string) string {
	if net.ParseIP(hostname) != nil {
		return hostname // É um IP, retorna ele mesmo.
	}

	result := tldExtractor.Extract(hostname)
	if result.Root == "" || result.Tld == "" {
		// Fallback para casos onde a biblioteca não consegue extrair (ex: localhost)
		return hostname
	}

	return fmt.Sprintf("%s.%s", result.Root, result.Tld)
}