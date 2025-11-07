package utils

import "redrecon/internal/config"

// GetGlobalProxy retorna o endereço do proxy a ser usado, seguindo uma ordem de prioridade.
// 1. Proxy Global (engine.proxy)
// 2. Proxy de Evasão (evasion.tor_proxy_address)
func GetGlobalProxy() string {
	// Prioridade 1: Proxy Global
	if config.Cfg != nil && config.Cfg.Engine.Proxy.Enabled && config.Cfg.Engine.Proxy.Address != "" {
		return config.Cfg.Engine.Proxy.Address
	}

	// Prioridade 2: Proxy de Evasão (Tor)
	if config.Cfg != nil && config.Cfg.Evasion.Enabled && config.Cfg.Evasion.UseTor && config.Cfg.Evasion.TorProxyAddress != "" {
		return config.Cfg.Evasion.TorProxyAddress
	}

	return ""
}