package env

import (
	"testing"
)

func TestLoadParsesExecutionIdentity(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "localhost:6276")
	t.Setenv("WORKER_TOKEN", "tok-1")
	t.Setenv("EXECUTION_ID", "exec-1")
	t.Setenv("JOB_ID", "job-1")
	t.Setenv("TOOL", "nuclei")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.WorkerAddr != "localhost:6276" {
		t.Errorf("WorkerAddr = %q, want localhost:6276", cfg.WorkerAddr)
	}
	if cfg.Token != "tok-1" {
		t.Errorf("Token = %q, want tok-1", cfg.Token)
	}
	if cfg.ExecutionID != "exec-1" {
		t.Errorf("ExecutionID = %q, want exec-1", cfg.ExecutionID)
	}
	if cfg.JobID != "job-1" {
		t.Errorf("JobID = %q, want job-1", cfg.JobID)
	}
	if cfg.Tool != "nuclei" {
		t.Errorf("Tool = %q, want nuclei", cfg.Tool)
	}
}

func TestLoadOptionalIdentityMissingIsEmpty(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "localhost:6276")
	t.Setenv("WORKER_TOKEN", "tok-1")
	// EXECUTION_ID, JOB_ID, TOOL intentionally unset. EXECUTION_ID is
	// mandatory without the opt-out; the opt-out keeps the legacy path valid.
	t.Setenv("OASM_ALLOW_LEGACY_NO_EXEC_ID", "1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load must not fail on missing optional vars: %v", err)
	}
	if cfg.ExecutionID != "" {
		t.Errorf("ExecutionID = %q, want empty", cfg.ExecutionID)
	}
	if cfg.JobID != "" {
		t.Errorf("JobID = %q, want empty", cfg.JobID)
	}
	if cfg.Tool != "" {
		t.Errorf("Tool = %q, want empty", cfg.Tool)
	}
	if cfg.WorkerAddr != "localhost:6276" {
		t.Errorf("WorkerAddr = %q, want localhost:6276", cfg.WorkerAddr)
	}
}

func TestLoadMissingAddrFails(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("EXECUTION_ID", "exec-1")

	if _, err := Load(); err == nil {
		t.Fatal("Load: want error when WORKER_GRPC_ADDR is missing")
	}
}
