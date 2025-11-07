package recon

import "redrecon/internal/config"

// GetEvasionProxy retorna o endereço do proxy Tor se a evasão estiver habilitada.
// Retorna uma string vazia caso contrário.
func GetEvasionProxy() string {
	evasionConfig := config.Cfg.Evasion
	if evasionConfig.Enabled && evasionConfig.UseTor && evasionConfig.TorProxyAddress != "" {
		return evasionConfig.TorProxyAddress
	}
	return ""
}