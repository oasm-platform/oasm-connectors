package runtime

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// TestRunFailsFastWhenExecutionIDMissing — Run must not silently register and
// then wait forever for an ExecuteJob that can never arrive (the worker
// routes jobs by execution identity). Missing EXECUTION_ID has to surface as
// a clear startup error instead of a hang.
func TestRunFailsFastWhenExecutionIDMissing(t *testing.T) {
	// No server listens on localhost:16276; success is Run refusing to dial.
	t.Setenv("WORKER_GRPC_ADDR", "localhost:16276")
	t.Setenv("EXECUTION_ID", "")
	t.Setenv("OASM_ALLOW_LEGACY_NO_EXEC_ID", "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- New(connector.New(&fakeAdapter{})).Run(ctx) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Run returned nil, want a clear EXECUTION_ID error")
		}
		if !strings.Contains(err.Error(), "EXECUTION_ID") {
			t.Errorf("Run error = %q, want it to mention EXECUTION_ID", err.Error())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run blocked instead of failing fast on missing EXECUTION_ID")
	}
}

// TestRunFailsFastWhenWorkerAddrMissing — the Worker always injects
// WORKER_GRPC_ADDR into connector containers, so a missing addr is a
// misconfiguration, not a legacy no-worker mode. Run must surface it as a
// clear startup error instead of blocking on ctx.Done(): with a Background
// context that would deadlock (nil Done channel → all goroutines asleep),
// which killed real connectors with exit=2. The 5s timeout turns any
// regression into a test failure instead of a hang.
func TestRunFailsFastWhenWorkerAddrMissing(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- New(connector.New(&fakeAdapter{})).Run(ctx) }()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Run returned nil, want a clear WORKER_GRPC_ADDR error")
		}
		if !strings.Contains(err.Error(), "WORKER_GRPC_ADDR") {
			t.Errorf("Run error = %q, want it to mention WORKER_GRPC_ADDR", err.Error())
		}
	case <-time.After(7 * time.Second):
		t.Fatal("Run blocked instead of failing fast on missing WORKER_GRPC_ADDR")
	}
}
