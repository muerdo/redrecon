package recon

import (
	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

// StepDiagnosticResult represents the result of a step health check
type StepDiagnosticResult struct {
	StepName string
	Passed   bool
	Message  string
}

// RunStepDiagnostics performs internal health checks on all recon steps
func RunStepDiagnostics() []StepDiagnosticResult {
	var results []StepDiagnosticResult

	// List of all known steps to check
	steps := []string{
		"passive", "probing", "ports", "web", "detection",
		"scan", "fuzzing", "technologies",
	}

	for _, step := range steps {
		results = append(results, checkSingleStep(step))
	}

	return results
}

func checkSingleStep(step string) StepDiagnosticResult {
	// Common check: verify if tools required for the step are configured and present
	// This goes beyond just "is the tool installed" to "is the step configuration valid"

	switch step {
	case "passive":
		return checkPassiveStep()
	case "probing":
		return checkProbingStep()
	case "ports":
		return checkPortsStep()
	case "web":
		return checkWebStep()
	default:
		return StepDiagnosticResult{
			StepName: step,
			Passed:   true,
			Message:  "No specific diagnostics defined (Generic check passed)",
		}
	}
}

func checkPassiveStep() StepDiagnosticResult {
	// Check if passive tools are enabled/configured
	if !config.Cfg.Tools.Subfinder.Enabled && !config.Cfg.Tools.Amass.Enabled {
		return StepDiagnosticResult{
			StepName: "passive",
			Passed:   false,
			Message:  "No passive subdomain tools enabled (Subfinder/Amass disabled)",
		}
	}

	// Check API keys for better passive results
	if config.Cfg.APIKeys.Chaos == "" && config.Cfg.APIKeys.SecurityTrails == "" {
		return StepDiagnosticResult{
			StepName: "passive",
			Passed:   true, // Warning only
			Message:  "Warning: No API keys configured for passive discovery (results will be limited)",
		}
	}

	return StepDiagnosticResult{StepName: "passive", Passed: true, Message: "OK"}
}

func checkProbingStep() StepDiagnosticResult {
	if !config.Cfg.Tools.Httpx.Enabled {
		return StepDiagnosticResult{
			StepName: "probing",
			Passed:   false,
			Message:  "Httpx tool is disabled, probing cannot function",
		}
	}
	return StepDiagnosticResult{StepName: "probing", Passed: true, Message: "OK"}
}

func checkPortsStep() StepDiagnosticResult {
	if !config.Cfg.Tools.Naabu.Enabled && !utils.CommandExists("nmap") {
		return StepDiagnosticResult{
			StepName: "ports",
			Passed:   false,
			Message:  "No port scanning tools available (Naabu disabled and Nmap not found)",
		}
	}
	return StepDiagnosticResult{StepName: "ports", Passed: true, Message: "OK"}
}

func checkWebStep() StepDiagnosticResult {
	if !config.Cfg.Tools.Feroxbuster.Enabled && !config.Cfg.Tools.Ffuf.Enabled {
		return StepDiagnosticResult{
			StepName: "web",
			Passed:   false,
			Message:  "No web fuzzing tools enabled (Feroxbuster/Ffuf disabled)",
		}
	}
	return StepDiagnosticResult{StepName: "web", Passed: true, Message: "OK"}
}
