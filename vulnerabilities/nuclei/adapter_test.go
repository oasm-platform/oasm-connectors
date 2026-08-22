package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ensureFakeNuclei builds the fake nuclei helper executable once and returns its path.
var (
	fakeBinOnce sync.Once
	fakeBinPath string
	fakeBinErr  error
)

func ensureFakeNuclei(t *testing.T) string {
	t.Helper()
	fakeBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-nuclei-*")
		if err != nil {
			fakeBinErr = err
			return
		}
		fakeBinPath = filepath.Join(dir, "fake-nuclei.exe")
		cmd := exec.Command("go", "build", "-o", fakeBinPath, "./testdata/fake-nuclei")
		if b, err := cmd.CombinedOutput(); err != nil {
			fakeBinErr = fmt.Errorf("build fake nuclei: %v: %s", err, b)
		}
	})
	if fakeBinErr != nil {
		t.Fatalf("fake nuclei unavailable: %v", fakeBinErr)
	}
	return fakeBinPath
}

// TestValidate_IsNoOp documents the contract: input validation happens upstream
// in the worker node layer; the connector must accept anything.
func TestValidate_IsNoOp(t *testing.T) {
	a := &NucleiAdapter{}
	for name, inputs := range map[string]map[string]any{
		"empty map":    {},
		"nil map":      nil,
		"garbage type": {"target": 123},
		"unknown keys": {"foo": "bar"},
	} {
		if err := a.Validate(context.Background(), inputs); err != nil {
			t.Errorf("%s: expected no-op Validate, got error: %v", name, err)
		}
	}
}

// TestNucleiExecute_MissingTargetErrors checks the presence check (argv needs it).
func TestNucleiExecute_MissingTargetErrors(t *testing.T) {
	t.Setenv("NUCLEI_BIN", "") // must fail before spawning any process
	a := &NucleiAdapter{}
	ch := make(chan []byte, 4)
	err := a.Execute(context.Background(), map[string]any{}, ch)
	if err == nil {
		t.Fatal("expected error for missing target")
	}
	if got := err.Error(); !strings.Contains(got, "target required") {
		t.Fatalf("want 'target required', got: %v", got)
	}
	select {
	case b := <-ch:
		t.Fatalf("nothing should be emitted, got: %s", b)
	default:
	}
}

// TestNucleiExecute_StreamsJsonlFindings is the happy path: JSONL findings are
// streamed through, banner/noise lines are skipped.
func TestNucleiExecute_StreamsJsonlFindings(t *testing.T) {
	t.Setenv("NUCLEI_BIN", ensureFakeNuclei(t))
	a := &NucleiAdapter{}
	ch := make(chan []byte, 8)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	close(ch)
	var findings []map[string]any
	for b := range ch {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("emitted line is not valid JSON object: %v (%s)", err, b)
		}
		findings = append(findings, m)
	}
	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 findings (noise skipped), got %d", len(findings))
	}
	wantIDs := []string{"cve-2023-1234", "cve-2024-5678"}
	for i, id := range wantIDs {
		if findings[i]["template-id"] != id {
			t.Errorf("finding[%d] template-id = %v, want %v", i, findings[i]["template-id"], id)
		}
	}
	if findings[0]["matched-at"] != "https://example.com" {
		t.Errorf("matched-at mismatch: %v", findings[0]["matched-at"])
	}
}

// TestNucleiExecute_EmptyOutputNoError: exit 0 with no output -> no error, no emission.
func TestNucleiExecute_EmptyOutputNoError(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	a := &NucleiAdapter{}
	ch := make(chan []byte, 4)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("expected nil error for empty output, got: %v", err)
	}
	select {
	case b := <-ch:
		t.Fatalf("nothing should be emitted, got: %s", b)
	default:
	}
}

// TestNucleiExecute_ReturnsErrorOnNonZeroExit: non-zero exit surfaces stderr.
func TestNucleiExecute_ReturnsErrorOnNonZeroExit(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "fail")
	a := &NucleiAdapter{}
	ch := make(chan []byte, 4)
	err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch)
	if err == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if got := err.Error(); !strings.Contains(got, "connection refused") {
		t.Fatalf("error should contain stderr fragment, got: %v", got)
	}
}
