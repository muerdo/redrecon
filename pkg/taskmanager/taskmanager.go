package taskmanager

import (
	"context"
	"fmt"
	"sync"
)

// manager é uma estrutura para gerenciar tarefas em andamento.
type manager struct {
	tasks map[string]context.CancelFunc
	mu    sync.Mutex
}

var (
	// tm é a instância singleton do nosso gerenciador de tarefas.
	tm = &manager{
		tasks: make(map[string]context.CancelFunc),
	}
)

// AddTask registra uma nova tarefa com sua função de cancelamento.
func AddTask(taskID string, cancel context.CancelFunc) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tm.tasks[taskID] = cancel
}

// RemoveTask remove uma tarefa do gerenciador, normalmente chamada quando a tarefa é concluída.
func RemoveTask(taskID string) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	delete(tm.tasks, taskID)
}

// StopTask encontra uma tarefa pelo seu ID, chama sua função de cancelamento e a remove.
func StopTask(taskID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	cancel, ok := tm.tasks[taskID]
	if !ok {
		return fmt.Errorf("tarefa '%s' não encontrada ou já concluída", taskID)
	}

	// Chama a função de cancelamento para parar a tarefa.
	cancel()

	// Remove a tarefa do mapa.
	delete(tm.tasks, taskID)
	return nil
}
