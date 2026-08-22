package lifecycle

import (
	"context"
	"fmt"
	"sync"
)

// State is the lifecycle state of a connector.
type State string

const (
	StateInit     State = "init"
	StateReady    State = "ready"
	StateRunning  State = "running"
	StateShutdown State = "shutdown"
)

// Lifecycle is a minimal state machine: init -> ready -> running -> shutdown.
// ponytail: ceiling is connect->ready->running->shutdown with Connect/Start/Stop/Shutdown;
// no reconnect/backoff here — that lives in transport/reconnect.
type Lifecycle struct {
	mu    sync.RWMutex
	state State
}

// New creates a Lifecycle in StateInit.
func New() *Lifecycle { return &Lifecycle{state: StateInit} }

// State returns the current state.
func (l *Lifecycle) State() State {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.state
}

// Connect transitions init -> ready. Takes target for API compat (currently unused; lazy dial).
func (l *Lifecycle) Connect(_ context.Context, _ string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == StateShutdown {
		return fmt.Errorf("invalid transition: shutdown -> ready")
	}
	if l.state != StateInit {
		return fmt.Errorf("invalid transition: %s -> ready (want init -> ready)", l.state)
	}
	l.state = StateReady
	return nil
}

// Start transitions ready -> running.
func (l *Lifecycle) Start() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state == StateShutdown {
		return fmt.Errorf("invalid transition: shutdown -> running")
	}
	if l.state != StateReady {
		return fmt.Errorf("invalid transition: %s -> running (want ready -> running)", l.state)
	}
	l.state = StateRunning
	return nil
}

// Stop transitions running -> shutdown (alias for Shutdown when running).
func (l *Lifecycle) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.state != StateRunning {
		return fmt.Errorf("invalid transition: %s -> shutdown (want running -> shutdown)", l.state)
	}
	l.state = StateShutdown
	return nil
}

// Shutdown transitions any non-shutdown state -> shutdown (idempotent).
func (l *Lifecycle) Shutdown() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.state = StateShutdown
}
