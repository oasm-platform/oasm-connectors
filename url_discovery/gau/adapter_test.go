package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

var (
	fakeGauPath string
	fakeGauOnce sync.Once
)

// ensureFakeGau builds the fake gau binary once for the test run. Uses
// os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeGau(t *testing.T) string {
	t.Helper()
	fakeGauOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-gau-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeGauPath = filepath.Join(dir, "fake-gau"+ext)
		cmd := exec.Command("go", "build", "-o", fakeGauPath, "./testdata/fake-gau")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build fake-gau: %v\n%s", err, out)
		}
	})
	return fakeGauPath
}

// collect runs Execute against the fake gau with FAKE_MODE=mode and returns the
// emitted findings plus the returned error.
func collect(t *testing.T, mode, target string) ([]connector.Finding, error) {
	t.Helper()
	bin := ensureFakeGau(t)
	t.Setenv("GAU_BIN", bin)
	t.Setenv("FAKE_MODE", mode)

	out := make(chan connector.Finding, 64)
	err := GauAdapter{}.Execute(context.Background(), map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

func TestValidate_IsNoOp(t *testing.T) {
	if err := (GauAdapter{}).Validate(context.Background(), nil); err != nil {
		t.Fatalf("Validate should return nil, got %v", err)
	}
}

// C1 happy: streams one Finding per unique URL, skipping duplicates and blanks.
func TestGauExecute_StreamsUrlFindings(t *testing.T) {
	findings, err := collect(t, "default", "https://example.com/a/b?x=1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d: %+v", len(findings), findings)
	}
	want := []string{
		"https://example.com/one",
		"https://example.com/two",
		"https://example.com/three",
	}
	for i, f := range findings {
		if f.Name != want[i] || f.MatchedAt != want[i] {
			t.Errorf("finding %d: Name=%q MatchedAt=%q, want %q", i, f.Name, f.MatchedAt, want[i])
		}
		if f.Severity != "info" {
			t.Errorf("finding %d: Severity=%q, want info", i, f.Severity)
		}
		if f.Host != "example.com" {
			t.Errorf("finding %d: Host=%q, want example.com", i, f.Host)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d invalid: %v", i, err)
		}
	}
}

// C2 edge: empty output is a clean, zero-findings success (not an error).
func TestGauExecute_EmptyOutputNoError(t *testing.T) {
	findings, err := collect(t, "empty", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// C3 edge: nonzero exit with no stdout is fatal; the error carries the stderr tail.
func TestGauExecute_NonZeroExitNoOutputIsError(t *testing.T) {
	findings, err := collect(t, "fail", "example.com")
	if err == nil {
		t.Fatal("expected error on nonzero exit with no output")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	msg := err.Error()
	if !contains(msg, "gau") {
		t.Errorf("error should mention gau, got: %s", msg)
	}
	if !contains(msg, "connection refused") {
		t.Errorf("error should carry the stderr tail, got: %s", msg)
	}
}

// C4 edge: nonzero exit WITH output is success (gau exit codes are unreliable).
func TestGauExecute_PartialOutputWithNonZeroExitSucceeds(t *testing.T) {
	findings, err := collect(t, "partial-fail", "example.com")
	if err != nil {
		t.Fatalf("partial output with nonzero exit must succeed, got %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

// C5 edge: a wedged gau is killed by the parent context deadline.
func TestGauExecute_ContextTimeoutKillsProcess(t *testing.T) {
	bin := ensureFakeGau(t)
	t.Setenv("GAU_BIN", bin)
	t.Setenv("FAKE_MODE", "hang")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	out := make(chan connector.Finding, 64)
	start := time.Now()
	err := GauAdapter{}.Execute(ctx, map[string]any{"target": "example.com"}, out)
	elapsed := time.Since(start)
	close(out)

	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
	if elapsed > 2*time.Second {
		t.Fatalf("Execute took %s, expected to return within ~2s", elapsed)
	}
	count := 0
	for range out {
		count++
	}
	if count != 0 {
		t.Fatalf("expected 0 findings, got %d", count)
	}
}

// C6 boundary: target normalization strips scheme/path/query/port.
func TestNormalizeTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com/a/b?x=1", "example.com"},
		{"example.com:443/x", "example.com"},
		{"   ", ""},
		{"http://EXAMPLE.com:8080", "EXAMPLE.com"},
		{"example.com", "example.com"},
	}
	for _, tc := range cases {
		if got := normalizeTarget(tc.in); got != tc.want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// C6 boundary: Execute rejects a missing/blank target.
func TestGauExecute_MissingTargetErrors(t *testing.T) {
	for _, inputs := range []map[string]any{{}, {"target": "   "}} {
		out := make(chan connector.Finding, 64)
		err := GauAdapter{}.Execute(context.Background(), inputs, out)
		close(out)
		if err == nil {
			t.Fatalf("expected error for inputs %+v", inputs)
		}
		if !contains(err.Error(), "target required") {
			t.Fatalf("expected 'target required', got: %s", err.Error())
		}
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
