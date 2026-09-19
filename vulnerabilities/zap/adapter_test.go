package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

var (
	fakeZapPath string
	fakeOnce    sync.Once
)

// ensureFakeZap builds the fake zap.sh once for the whole test run. Uses
// os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeZap(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-zap-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeZapPath = filepath.Join(dir, "fake-zap"+ext)
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", fakeZapPath, "./testdata/fake-zap")
		cmd.Dir = "."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build fake-zap: %v\n%s", err, out)
		}
	})
	return fakeZapPath
}

// runAdapter executes the adapter against the fake with the given FAKE_MODE
// and returns the collected findings plus the adapter error.
func runAdapter(t *testing.T, mode string) ([]connector.Finding, error) {
	t.Helper()
	bin := ensureFakeZap(t)
	t.Setenv("ZAP_BIN", bin)
	t.Setenv("FAKE_MODE", mode)
	t.Setenv("OASM_CONFIG", "")

	out := make(chan connector.Finding, 64)
	err := (&ZapAdapter{}).Execute(context.Background(), map[string]any{"target": "example.com"}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

func TestValidate_IsNoOp(t *testing.T) {
	if err := (&ZapAdapter{}).Validate(context.Background(), nil); err != nil {
		t.Fatalf("Validate should return nil, got %v", err)
	}
}

func TestExecute_MissingTargetErrors(t *testing.T) {
	out := make(chan connector.Finding, 8)
	err := (&ZapAdapter{}).Execute(context.Background(), map[string]any{}, out)
	close(out)
	if err == nil || !strings.Contains(err.Error(), "target required") {
		t.Fatalf("expected 'target required', got %v", err)
	}
}

func TestExecute_StreamsFindings(t *testing.T) {
	findings, err := runAdapter(t, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	f := findings[0]
	if f.Name != "Cross Site Scripting (Reflected)" {
		t.Errorf("Name = %q", f.Name)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Host != "example.com" {
		t.Errorf("Host = %q", f.Host)
	}
	if err := f.Validate(); err != nil {
		t.Errorf("finding failed SDK validation: %v", err)
	}
}

func TestExecute_NonZeroExitWithReportIsSuccess(t *testing.T) {
	// ZAP exits 1 on warnings/errors; a parseable report still wins.
	findings, err := runAdapter(t, "error")
	if err != nil {
		t.Fatalf("nonzero exit with a valid report must not be fatal: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestExecute_WarningExitWithReportIsSuccess(t *testing.T) {
	findings, err := runAdapter(t, "warn")
	if err != nil {
		t.Fatalf("exit 2 with a valid report must not be fatal: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

func TestExecute_MissingReportIsFatal(t *testing.T) {
	_, err := runAdapter(t, "noreport")
	if err == nil {
		t.Fatal("expected error when no report is produced")
	}
}

func TestExecute_InvalidReportErrors(t *testing.T) {
	_, err := runAdapter(t, "garbage")
	if err == nil || !strings.Contains(err.Error(), "parse zap report") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestExecute_EmptyReportZeroFindings(t *testing.T) {
	findings, err := runAdapter(t, "empty")
	if err != nil {
		t.Fatalf("empty report must be a clean success: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestExecute_InvokesZapWithAutomationFlags(t *testing.T) {
	bin := ensureFakeZap(t)
	t.Setenv("ZAP_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", "")

	argsFile := filepath.Join(t.TempDir(), "args.json")
	t.Setenv("FAKE_ARGS_FILE", argsFile)

	out := make(chan connector.Finding, 8)
	err := (&ZapAdapter{}).Execute(context.Background(), map[string]any{"target": "example.com"}, out)
	close(out)
	for range out {
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatalf("decode args: %v", err)
	}
	for _, want := range []string{"-cmd", "-silent", "-nostdout", "-autorun", "-dir"} {
		if !contains(args, want) {
			t.Errorf("missing %q in args %v", want, args)
		}
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
