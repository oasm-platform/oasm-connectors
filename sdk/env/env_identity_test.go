package env

import (
	"errors"
	"strings"
	"testing"
)

// TestLoadRequiresExecutionIDUnlessOptOut — fail-fast contract: a connector
// that connects to a Worker without an execution identity registers fine but
// never receives ExecuteJob (the worker routes by identity) — it just hangs.
// Load must reject the missing EXECUTION_ID with a clear error that names the
// opt-out. OASM_ALLOW_LEGACY_NO_EXEC_ID preserves the legacy no-identity path.
func TestLoadRequiresExecutionIDUnlessOptOut(t *testing.T) {
	t.Run("missing EXECUTION_ID errors", func(t *testing.T) {
		t.Setenv("WORKER_GRPC_ADDR", "localhost:16276")
		t.Setenv("EXECUTION_ID", "")
		t.Setenv("OASM_ALLOW_LEGACY_NO_EXEC_ID", "")

		_, err := Load()
		if err == nil {
			t.Fatal("Load: want error when EXECUTION_ID is missing")
		}
		if !errors.Is(err, ErrExecutionIDMissing) {
			t.Errorf("Load error = %v, want it to wrap ErrExecutionIDMissing", err)
		}
		if !strings.Contains(err.Error(), "OASM_ALLOW_LEGACY_NO_EXEC_ID") {
			t.Errorf("Load error must name OASM_ALLOW_LEGACY_NO_EXEC_ID, got %q", err.Error())
		}
	})

	t.Run("present EXECUTION_ID ok", func(t *testing.T) {
		t.Setenv("WORKER_GRPC_ADDR", "localhost:16276")
		t.Setenv("EXECUTION_ID", "exec-1")
		t.Setenv("OASM_ALLOW_LEGACY_NO_EXEC_ID", "")

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.ExecutionID != "exec-1" {
			t.Errorf("ExecutionID = %q, want exec-1", cfg.ExecutionID)
		}
	})

	t.Run("opt-out allows missing EXECUTION_ID", func(t *testing.T) {
		t.Setenv("WORKER_GRPC_ADDR", "localhost:16276")
		t.Setenv("EXECUTION_ID", "")
		t.Setenv("OASM_ALLOW_LEGACY_NO_EXEC_ID", "1")

		if _, err := Load(); err != nil {
			t.Fatalf("Load with OASM_ALLOW_LEGACY_NO_EXEC_ID set must succeed, got %v", err)
		}
	})
}
