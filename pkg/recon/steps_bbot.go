package recon

import (
	"path/filepath"
	"redrecon/pkg/types"
	"redrecon/pkg/utils"
	"strings"
)

func extractTechFromFindings(findings []types.BBotFinding) []string {
	var tech []string
	for _, f := range findings {
		if f.Type == "TECHNOLOGY" {
			if t, ok := f.Data.(string); ok {
				tech = append(tech, t)
			} else if ts, ok := f.Data.([]string); ok {
				tech = append(tech, ts...)
			}
		}
	}
	return tech
}

func decideBBotModules(tech []string) string {
	// Base de módulos: descoberta, scan de portas, análise web básica, scan de vulnerabilidades genéricas,
	// checagens de nuvem, busca por segredos e enumeração de buckets.
	modules := "subdomain-enum,portscan,web-basic,vulnscan,cloudcheck,excavate,speculate,bucket-enum"

	// Mapeamento de tecnologias para módulos do bbot.
	// A chave é a string a ser encontrada (case-insensitive) na lista de tecnologias.
	// O valor é o nome do módulo a ser adicionado.
	techModuleMap := map[string]string{
		"wordpress":    "wordpress",
		"joomla":       "joomla",
		"drupal":       "drupal",
		"magento":      "magento",
		"sharepoint":   "sharepoint",
		"coldfusion":   "coldfusion",
		"liferay":      "liferay",
		"apache":       "apache",
		"nginx":        "nginx",
		"iis":          "iis",
		"tomcat":       "tomcat",
		"jboss":        "jboss",
		"weblogic":     "weblogic",
		"websphere":    "websphere",
		"spring":       "spring",
		"struts":       "struts",
		"jenkins":      "jenkins",
		"gitlab":       "gitlab",
		"jira":         "jira",
		"confluence":   "confluence",
		"nexus":        "nexus",
		"artifactory":  "artifactory",
		"php":          "php",
		"laravel":      "laravel",
		"symfony":      "symfony",
		"python":       "python",
		"django":       "django",
		"flask":        "flask",
		"ruby":         "ruby",
		"rails":        "rails",
		"java":         "java",
		"node.js":      "nodejs",
		"express":      "express",
		"kubernetes":   "kubernetes",
		"docker":       "docker",
		"api":          "api_discovery",
		"aws":          "cloud_enum",
		"azure":        "cloud_enum",
		"gcp":          "cloud_enum",
	}

	lower := make([]string, len(tech))
	for i, t := range tech {
		lower[i] = strings.ToLower(t)
	}

	addedModules := make(map[string]bool)
	for techName, moduleName := range techModuleMap {
		if contains(lower, techName) {
			if _, exists := addedModules[moduleName]; !exists {
				modules += "," + moduleName
				addedModules[moduleName] = true
			}
		}
	}

	return modules
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.Contains(s, item) {
			return true
		}
	}
	return false
}

func extractBBotData(findings []types.BBotFinding, state *reconState, outDir string) {
	var live, urls []string
	for _, f := range findings {
		if data, ok := f.Data.(string); ok {
			switch f.Type {
			case "OPEN_TCP_PORT", "HTTP_SERVICE":
				if !strings.Contains(data, "://") {
					data = "http://" + data
				}
				live = append(live, data)
			case "URL":
				urls = append(urls, data)
			}
		}
	}
	write := func(name string, data []string) {
		path := filepath.Join(outDir, name)
		_ = utils.WriteLines(path, utils.UniqueStrings(data))
	}
	write("live_hosts.txt", live)
	write("urls.txt", urls)

	state.bbotLiveHostsFile = filepath.Join(outDir, "live_hosts.txt")
	state.bbotURLsFile = filepath.Join(outDir, "urls.txt")
	state.logger.Info("BBOT", "live", len(live), "urls", len(urls))
}