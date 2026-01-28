package recon

import (
	"redrecon/internal/config"
)

// CTFProfile defines optimizations for CTF environments
type CTFProfile struct {
	MaxConcurrency        int
	Timeout               int
	StealthMode           bool
	QuickScan             bool
	DisableSlowTools      bool
	AggressiveEnumeration bool
}

// GetCTFProfile returns the default CTF optimization profile
func GetCTFProfile() CTFProfile {
	return CTFProfile{
		MaxConcurrency:        2,     // Low concurrency to avoid detection
		Timeout:               60,    // 1 minute max per tool (not 15!)
		StealthMode:           true,  // Rate limiting enabled
		QuickScan:             true,  // Skip slow tools
		DisableSlowTools:      true,  // Disable bbot, amass, etc
		AggressiveEnumeration: false, // Don't be too noisy
	}
}

// ApplyCTFOptimizations modifies config for CTF context
func ApplyCTFOptimizations(cfg *config.Config) {
	profile := GetCTFProfile()

	// Reduce timeouts dramatically
	cfg.Tools.Nuclei.Timeout = profile.Timeout
	cfg.Tools.Nuclei.Concurrency = profile.MaxConcurrency
	cfg.Tools.Nuclei.RateLimit = 10 // Slower rate

	// Disable slow/noisy tools
	if profile.DisableSlowTools {
		cfg.Tools.Bbot.Enabled = false       // Very slow (correct: Bbot not BBot)
		cfg.Tools.Amass.Enabled = false      // Very slow
		cfg.Tools.Nikto.Enabled = false      // Very noisy
		cfg.Recon.Shuffledns.Enabled = false // Slow brute-force
	}

	// Enable fast, effective tools
	cfg.Tools.Subfinder.Enabled = true
	cfg.Tools.Httpx.Enabled = true
	cfg.Tools.Nuclei.Enabled = true
	cfg.Tools.Feroxbuster.Enabled = true
	cfg.Tools.Naabu.Enabled = true

	// Stealth mode settings
	if profile.StealthMode {
		// Create or update CTF WAF profile
		if cfg.Engine.WAF.Profiles == nil {
			cfg.Engine.WAF.Profiles = make(map[string]config.WAFProfile)
		}

		cfg.Engine.WAF.Profiles["ctf"] = config.WAFProfile{
			RateLimit:   2, // 2 req/s - very conservative
			Concurrency: 1, // Single thread
			ProxyFile:   "",
			Proxies:     []string{},
		}
		cfg.Engine.WAF.DefaultProfile = "ctf"
	}

	// Optimize resource limits for CTF boxes (often limited resources)
	cfg.Engine.ResourceLimits.CPUThreshold = 40.0 // Lower threshold
	cfg.Engine.ResourceLimits.RAMThreshold = 40.0 // Lower threshold
	cfg.Engine.MaxParallelTasks = 2               // Max 2 tools at once

	// Quick enumeration settings
	if profile.QuickScan {
		cfg.Tools.Subfinder.Threads = 20   // Reduced from 50
		cfg.Tools.Httpx.Threads = 20       // Reduced from 50
		cfg.Tools.Feroxbuster.Threads = 20 // Reduced from 50
	}
}

// GetCTFRecommendedSteps returns recommended recon steps for CTF
func GetCTFRecommendedSteps() []string {
	return []string{
		"passive",   // Passive subdomain enumeration (fast)
		"probing",   // HTTP probing (essential)
		"ports",     // Port scanning (essential for CTF)
		"web",       // Web crawling (if web app)
		"detection", // WAF/tech detection
		// Skip: bbot, analysis (too slow)
	}
}

// ShouldSkipStep checks if a step should be skipped in CTF mode
func ShouldSkipStep(step string, ctfMode bool) bool {
	if !ctfMode {
		return false
	}

	slowSteps := map[string]bool{
		"bbot":     true,
		"analysis": true,
		"secrets":  true, // Can be slow on large codebases
	}

	return slowSteps[step]
}
