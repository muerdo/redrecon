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
	domainRegex = regexp.MustCompile(`([a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.)+[a-zA-Z]{2,}`)
	ipRegex     = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
)

var tldExtractor, _ = tldextract.New("tld.cache", true)

func IsTargetFile(target string) bool {
	info, err := os.Stat(target)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func IsTargetDirectory(target string) bool {
	info, err := os.Stat(target)
	if os.IsNotExist(err) {
		return false
	}
	return info.IsDir()
}

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
	default:
		targets = extractTargetsFromText(file)
	}

	return normalizeTargets(targets), nil
}

func ParseTargetDirectory(dirPath string) ([]string, error) {
	allTargets := make(map[string]struct{})

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileTargets, err := ParseTargetFile(path)
			if err != nil {
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

func extractTargetsFromXML(reader io.Reader) []string {
	var nmapRun NmapRun
	if err := xml.NewDecoder(reader).Decode(&nmapRun); err != nil {
		if seeker, ok := reader.(io.ReadSeeker); ok {
			seeker.Seek(0, io.SeekStart)
			return extractTargetsFromText(seeker)
		}
		return nil
	}

	var targets []string
	for _, host := range nmapRun.Hosts {
		for _, hostname := range host.Hostnames.Hostname {
			if hostname.Name != "" {
				targets = append(targets, hostname.Name)
			}
		}
		for _, addr := range host.Addresses {
			if addr.AddrType == "ipv4" || addr.AddrType == "ipv6" {
				targets = append(targets, addr.Addr)
			}
		}
	}
	return targets
}

func normalizeTargets(targets []string) []string {
	normalized := make(map[string]struct{})
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

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

func GetRootDomain(hostname string) string {
	if net.ParseIP(hostname) != nil {
		return hostname
	}

	result := tldExtractor.Extract(hostname)
	if result.Root == "" || result.Tld == "" {
		return hostname
	}

	return fmt.Sprintf("%s.%s", result.Root, result.Tld)
}