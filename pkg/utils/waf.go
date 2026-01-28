package utils

import (
	"fmt"
	"log/slog"
	"redrecon/internal/config"
)

// GetActiveWAFProfile determina o perfil WAF a ser usado.
// Retorna o perfil WAF ativo e um booleano indicando se um perfil foi encontrado.
func GetActiveWAFProfile(logger *slog.Logger, wafName string, tempDir string) (config.WAFProfile, bool) {
	if !config.Cfg.Engine.WAF.Enabled {
		return config.WAFProfile{}, false
	}

	// Tenta obter o perfil específico do WAF detectado
	if profile, ok := config.Cfg.Engine.WAF.Profiles[wafName]; ok {
		logger.Debug("Using specific WAF profile", "waf", wafName)
		return profile, true
	}

	// Se não encontrar, usa o perfil padrão
	defaultProfileName := config.Cfg.Engine.WAF.DefaultProfile
	if profile, ok := config.Cfg.Engine.WAF.Profiles[defaultProfileName]; ok {
		logger.Debug("Using default WAF profile", "profile_name", defaultProfileName)
		return profile, true
	}

	// Suppress warning if it's just a missing default, use Debug instead
	logger.Debug("WAF profile not found, even the default one. Proceeding without specific WAF profile.", "requested_waf", wafName, "default_profile", defaultProfileName)
	return config.WAFProfile{}, false // Fallback
}

// GetWAFProxyEnv retorna as variáveis de ambiente de proxy com base no perfil WAF.
func GetWAFProxyEnv(useTor bool) []string {
	if useTor && config.Cfg.Engine.WAF.TorProxy != "" {
		proxy := config.Cfg.Engine.WAF.TorProxy
		return []string{fmt.Sprintf("HTTPS_PROXY=%s", proxy), fmt.Sprintf("HTTP_PROXY=%s", proxy)}
	}
	return nil
}
