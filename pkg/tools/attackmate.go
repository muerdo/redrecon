package tools

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"redrecon/internal/config"
	"redrecon/pkg/utils"
)

// AttackMate struct para encapsular o logger.
type AttackMate struct{ logger *slog.Logger }

// NewAttackMate cria uma nova instância de AttackMate.
func NewAttackMate(l *slog.Logger) *AttackMate { return &AttackMate{l} }

// Run executa um playbook do AttackMate.
func (a *AttackMate) Run(ctx context.Context, playbook, input, output string, rl, conc int, proxy string) error {
	if !config.Cfg.Orchestration.AttackMate.Enabled {
		a.logger.Info("AttackMate is disabled in configuration. Skipping.")
		return nil
	}
	bin := config.GetToolPath("attackmate")
	if bin == "attackmate" { // Fallback se não encontrar no PATH ou config
		a.logger.Warn("AttackMate executable not found in PATH or configured path. Please ensure it's installed and accessible.", "tool", "attackmate")
		return fmt.Errorf("attackmate executable not found")
	}

	if err := os.MkdirAll(filepath.Dir(output), 0755); err != nil {
		return fmt.Errorf("failed to create output directory for attackmate: %w", err)
	}

	args := []string{"run", playbook, "--input", input, "--output", output, "--log-level", "info"}
	if rl > 0 {
		args = append(args, "--rate-limit", fmt.Sprint(rl))
	}
	if conc > 0 {
		args = append(args, "--concurrency", fmt.Sprint(conc))
	}
	if proxy != "" {
		args = append(args, "--proxy", proxy)
	}

	a.logger.Info("Running AttackMate playbook", "playbook", filepath.Base(playbook), "input", input, "output", output)
	_, err := utils.ExecuteCommand(ctx, a.logger, bin, args...)
	if err != nil {
		a.logger.Error("AttackMate playbook failed", "playbook", filepath.Base(playbook), "error", err)
		return fmt.Errorf("attackmate playbook execution failed: %w", err)
	}
	a.logger.Info("AttackMate playbook completed successfully", "playbook", filepath.Base(playbook))
	return nil
}