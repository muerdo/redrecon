package types

import "fmt"

// Finding é uma interface que representa um achado de segurança genérico de qualquer ferramenta.
// Qualquer tipo que implemente todos os métodos desta interface pode ser tratado como um Finding.
type Finding interface {
	// String deve retornar um resumo de uma linha do achado.
	String() string
	// GetSeverity deve retornar o nível de severidade (ex: "high", "medium", "low").
	GetSeverity() string
	// GetTool deve retornar o nome da ferramenta que gerou o achado.
	GetTool() string
	// GetType deve retornar o tipo do achado (ex: "Secret", "Vulnerability").
	GetType() string
}

// SecretFinding representa um segredo descoberto por uma ferramenta como o TruffleHog.
type SecretFinding struct {
	Type     string
	Secret   string
	File     string
	Line     int
	Severity string
	Evidence string
}

// String implementa o método String() para a interface Finding.
// Isso garante que um *SecretFinding possa ser tratado como um Finding.
func (sf *SecretFinding) String() string {
	return fmt.Sprintf("[%s] Secret of type '%s' found in %s at line %d. Evidence: %s", sf.Severity, sf.Type, sf.File, sf.Line, sf.Evidence)
}

// GetSeverity implementa o método GetSeverity() para a interface Finding.
func (sf *SecretFinding) GetSeverity() string {
	return sf.Severity
}

// GetTool implementa o método GetTool() para a interface Finding.
func (sf *SecretFinding) GetTool() string {
	return "trufflehog" // TruffleHog é a principal fonte para SecretFinding
}

// GetType implementa o método GetType() para a interface Finding.
func (sf *SecretFinding) GetType() string {
	return sf.Type
}

// AttackMateFinding representa um achado da ferramenta AttackMate.
type AttackMateFinding struct {
	Tool     string
	Target   string
	Evidence string
	Severity string
}

// String implementa o método String() para a interface Finding.
func (af *AttackMateFinding) String() string {
	return fmt.Sprintf("[%s] AttackMate finding for target '%s'. Evidence: %s", af.Severity, af.Target, af.Evidence)
}

// GetSeverity implementa o método GetSeverity() para a interface Finding.
func (af *AttackMateFinding) GetSeverity() string {
	return af.Severity
}

// GetTool implementa o método GetTool() para a interface Finding.
func (af *AttackMateFinding) GetTool() string {
	return af.Tool
}

// GetType implementa o método GetType() para a interface Finding.
func (af *AttackMateFinding) GetType() string {
	return "AttackMate Finding" // Retorna um tipo genérico para este achado.
}

// MetasploitFinding representa uma sugestão de módulo do Metasploit como um achado.
type MetasploitFinding struct {
	Tool        string
	Target      string
	Module      string
	Evidence    string
	Severity    string
}

// String implementa o método String() para a interface Finding.
func (mf *MetasploitFinding) String() string {
	return fmt.Sprintf("[%s] Metasploit finding for %s (module: %s). Evidence: %s", mf.Severity, mf.Target, mf.Module, mf.Evidence)
}

// GetSeverity implementa o método GetSeverity() para a interface Finding.
func (mf *MetasploitFinding) GetSeverity() string {
	return mf.Severity
}

// GetTool implementa o método GetTool() para a interface Finding.
func (mf *MetasploitFinding) GetTool() string {
	return mf.Tool
}

// GetType implementa o método GetType() para a interface Finding.
func (mf *MetasploitFinding) GetType() string {
	return "Metasploit Suggestion"
}

// ContentFinding representa um achado (segredo ou endpoint) da análise de conteúdo de arquivos.
type ContentFinding struct {
	Tool     string
	Evidence string
	Severity string
	FType    string // "Secret" ou "Endpoint"
}

// String implementa o método String() para a interface Finding.
func (cf *ContentFinding) String() string {
	return fmt.Sprintf("[%s] Content analysis found %s: %s", cf.Severity, cf.FType, cf.Evidence)
}

// GetSeverity implementa o método GetSeverity() para a interface Finding.
func (cf *ContentFinding) GetSeverity() string {
	return cf.Severity
}

// GetTool implementa o método GetTool() para a interface Finding.
func (cf *ContentFinding) GetTool() string {
	return cf.Tool
}

// GetType implementa o método GetType() para a interface Finding.
func (cf *ContentFinding) GetType() string {
	return cf.FType
}