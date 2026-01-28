package utils

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
)

// FileExists checks if a file exists.
func FileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	return !os.IsNotExist(err)
}

// FileExistsAndIsNotEmpty checks if a file exists and is not empty.
// This function is assumed to be needed based on its usage in steps_nuclei.go
func FileExistsAndIsNotEmpty(filePath string) bool {
	info, err := os.Stat(filePath)
	if os.IsNotExist(err) {
		return false
	}
	return err == nil && info.Size() > 0
}

// WriteJSON writes data to a file in JSON format.
func WriteJSON(filePath string, data interface{}) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Para formatação legível
	return encoder.Encode(data)
}

// WriteLines writes a slice of strings to a file, each on a new line.
func WriteLines(filePath string, lines []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		_, err := file.WriteString(line + "\n")
		if err != nil {
			return err
		}
	}
	return nil
}

// Contains checks if a string slice contains um item específico (correspondência de substring sem distinção entre maiúsculas e minúsculas).
func Contains(slice []string, item string) bool {
	for _, s := range slice {
		// Usando strings.Contains para correspondência de substring, conforme implícito pela função 'contains' original
		// Se for necessária uma correspondência exata, altere para `s == item`
		if strings.Contains(s, item) {
			return true
		}
	}
	return false
}

// OpenFileAppend opens a file for appending, creating it if necessary.
func OpenFileAppend(filePath string) (*os.File, error) {
	return os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
}

var pathSanitizer = strings.NewReplacer(
	"/", "_",
	"\\", "_",
	":", "_",
	"*", "_",
	"?", "_",
	"\"", "_",
	"<", "_",
	">", "_",
	"|", "_",
)

// SanitizeTargetForPath substitui caracteres inválidos em nomes de arquivo/caminho.
func SanitizeTargetForPath(target string) string {
	return pathSanitizer.Replace(target)
}

// DirExistsAndIsNotEmpty verifica se um diretório existe e não está vazio.
func DirExistsAndIsNotEmpty(path string) bool {
	info, err := os.Stat(path)
	if os.IsNotExist(err) || !info.IsDir() {
		return false
	}

	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	_, err = f.Readdirnames(1) // Tenta ler pelo menos uma entrada.
	return err != io.EOF
}

// FIX: Adicionando IsValidIP ao pacote utils para reuso em outros pacotes.
// IsValidIP verifica se uma string é um endereço IP válido.
func IsValidIP(address string) bool {
	parsedIP := net.ParseIP(address)
	return parsedIP != nil
}

// ExtractDomainsFromURLFile reads a file containing URLs or domains and extracts unique domains/hostnames to a new file.
func ExtractDomainsFromURLFile(inputFile, outputFile string) error {
	lines, err := ReadLines(inputFile)
	if err != nil {
		return err
	}

	uniqueDomains := make(map[string]struct{})
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to parse as URL
		u, err := url.Parse(line)
		if err == nil && u.Host != "" {
			// Remove port if present
			host := u.Host
			if strings.Contains(host, ":") {
				h, _, err := net.SplitHostPort(host)
				if err == nil {
					host = h
				}
			}
			uniqueDomains[host] = struct{}{}
		} else {
			// Assume it's already a domain or IP
			// Remove port if present
			host := line
			if strings.Contains(host, ":") {
				h, _, err := net.SplitHostPort(host)
				if err == nil {
					host = h
				}
			}
			uniqueDomains[host] = struct{}{}
		}
	}

	var domains []string
	for d := range uniqueDomains {
		domains = append(domains, d)
	}

	return WriteLines(outputFile, domains)
}

// StringSliceFlag é um tipo customizado para flags que aceitam múltiplos valores de string.
type StringSliceFlag []string

// String é o método para formatar o valor da flag (parte da interface pflag.Value).
func (s *StringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

// Set é o método para definir o valor da flag (parte da interface pflag.Value).
func (s *StringSliceFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// Type é o método para retornar o tipo da flag (parte da interface pflag.Value).
func (s *StringSliceFlag) Type() string {
	return "stringSlice"
}

// ProxyManager gerencia uma lista de proxies e os distribui de forma rotativa.
type ProxyManager struct {
	proxies   []string
	proxyType string
	mu        sync.Mutex
	next      int
	filePath  string // Path to proxy file for reloading
}

// NewProxyManager cria um novo gerenciador de proxies.
func NewProxyManager(proxyType string, proxies []string) *ProxyManager {
	return &ProxyManager{
		proxies:   proxies,
		proxyType: strings.ToLower(proxyType),
	}
}

// NewProxyManagerFromList cria um novo gerenciador de proxies a partir de uma lista de strings.
// Se a lista for vazia ou nula, retorna nil.
func NewProxyManagerFromList(proxies []string) *ProxyManager {
	if len(proxies) == 0 {
		return nil
	}
	// O tipo é inferido a partir do esquema na URL do proxy (http, socks5, etc.)
	// A lógica em GetNextProxy já lida com isso.
	// Default to http if not specified
	return NewProxyManager("http", proxies)
}

// GetNextProxy retorna o próximo proxy da lista no formato de URL completo.
func (pm *ProxyManager) GetNextProxy() string {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	if len(pm.proxies) == 0 {
		return ""
	}
	proxy := pm.proxies[pm.next]
	pm.next = (pm.next + 1) % len(pm.proxies)

	// Garante que o proxy tenha o esquema correto (http, socks5, etc.)
	if !strings.Contains(proxy, "://") {
		scheme := pm.proxyType
		if scheme == "sock4" {
			scheme = "socks4" // Normaliza para o esquema correto
		}
		if scheme == "sock5" {
			scheme = "socks5" // Normaliza para o esquema correto
		}
		return fmt.Sprintf("%s://%s", scheme, proxy)
	}
	return proxy
}

// LoadFromFile loads proxies from a file and replaces the current proxy list
func (pm *ProxyManager) LoadFromFile(filePath string) error {
	proxies, err := LoadProxiesFromFile(filePath)
	if err != nil {
		return err
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	pm.proxies = proxies
	pm.filePath = filePath
	pm.next = 0 // Reset rotation counter

	return nil
}

// ReloadProxies reloads proxies from the stored file path
func (pm *ProxyManager) ReloadProxies() error {
	if pm.filePath == "" {
		return fmt.Errorf("no file path set for proxy reloading")
	}
	return pm.LoadFromFile(pm.filePath)
}

// GetProxyCount returns the number of proxies currently loaded
func (pm *ProxyManager) GetProxyCount() int {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	return len(pm.proxies)
}

// NewProxyManagerFromFile creates a ProxyManager by loading proxies from a file
func NewProxyManagerFromFile(filePath string) (*ProxyManager, error) {
	proxies, err := LoadProxiesFromFile(filePath)
	if err != nil {
		return nil, err
	}

	pm := NewProxyManager("socks5", proxies)
	pm.filePath = filePath
	return pm, nil
}

// ResolveIPs reads a file containing domains, resolves them to IPs, and writes unique IPs to an output file.
func ResolveIPs(inputFile, outputFile string) error {
	lines, err := ReadLines(inputFile)
	if err != nil {
		return err
	}

	uniqueIPs := make(map[string]struct{})
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Channel for domains to resolve
	domainChan := make(chan string, 100)

	// Worker pool
	concurrency := 50
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for line := range domainChan {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}

				// If it's already an IP, add it directly
				if IsValidIP(line) {
					mu.Lock()
					uniqueIPs[line] = struct{}{}
					mu.Unlock()
					continue
				}

				// Resolve domain
				ips, err := net.LookupIP(line)
				if err != nil {
					continue
				}

				mu.Lock()
				for _, ip := range ips {
					uniqueIPs[ip.String()] = struct{}{}
				}
				mu.Unlock()
			}
		}()
	}

	// Feed domains to channel
	for _, line := range lines {
		domainChan <- line
	}
	close(domainChan)

	wg.Wait()

	var ips []string
	for ip := range uniqueIPs {
		ips = append(ips, ip)
	}

	return WriteLines(outputFile, ips)
}

// ResolveIPsForTarget resolves a single domain to its IPs.
func ResolveIPsForTarget(target string) ([]string, error) {
	if IsValidIP(target) {
		return []string{target}, nil
	}
	ips, err := net.LookupIP(target)
	if err != nil {
		return nil, err
	}
	var ipStrings []string
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.String())
	}
	return ipStrings, nil
}

// BasicAuthHeader returns the Basic Auth header value for the given username and password.
func BasicAuthHeader(username, password string) string {
	auth := username + ":" + password
	return "Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(auth))
}

// ExtractDomain extracts the domain/hostname from a URL string.
func ExtractDomain(urlStr string) string {
	if !strings.Contains(urlStr, "://") {
		urlStr = "http://" + urlStr
	}
	u, err := url.Parse(urlStr)
	if err != nil {
		return urlStr
	}
	return u.Hostname()
}

// AppendToFile appends a string to a file.
func AppendToFile(filePath, content string) error {
	// Ensure the string ends with a newline if the content doesn't have one and file is not empty?
	// For simplicity, we just append exactly what is given.
	// The caller should handle newlines if needed, or we can ensure it?
	// In the pipeline usage: `utils.AppendToFile(p.state.liveSubdomainsFile, string(content))`
	// `content` from ReadFile usually has newlines if the file had them.

	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(content); err != nil {
		return err
	}
	return nil
}

// SanitizeFilename cleans a string to be used as a filename.
func SanitizeFilename(name string) string {
	return pathSanitizer.Replace(name)
}
