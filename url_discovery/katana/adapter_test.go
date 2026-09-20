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
	fakeKatanaPath string
	fakeKatanaOnce sync.Once
)

// ensureFakeKatana builds the fake katana binary once for the test run. Uses
// os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeKatana(t *testing.T) string {
	t.Helper()
	fakeKatanaOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-katana-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeKatanaPath = filepath.Join(dir, "fake-katana"+ext)
		cmd := exec.Command("go", "build", "-o", fakeKatanaPath, "./testdata/fake-katana")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build fake-katana: %v\n%s", err, out)
		}
	})
	return fakeKatanaPath
}

// collect runs Execute against the fake katana with FAKE_MODE=mode and returns
// the emitted findings plus the returned error.
func collect(t *testing.T, mode, target string) ([]connector.Finding, error) {
	t.Helper()
	bin := ensureFakeKatana(t)
	t.Setenv("KATANA_BIN", bin)
	t.Setenv("FAKE_MODE", mode)

	out := make(chan connector.Finding, 64)
	err := KatanaAdapter{}.Execute(context.Background(), map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

func TestValidate_IsNoOp(t *testing.T) {
	if err := (KatanaAdapter{}).Validate(context.Background(), nil); err != nil {
		t.Fatalf("Validate should return nil, got %v", err)
	}
}

// S2 happy: streams one Finding per unique http(s) URL, dropping blanks,
// non-http schemes (katana emits ftp:/mailto:) and duplicates.
func TestKatanaExecute_StreamsUrlFindings(t *testing.T) {
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
		if !contains(f.Name, "http://") && !contains(f.Name, "https://") {
			t.Errorf("finding %d: Name=%q is not an http(s) URL", i, f.Name)
		}
	}
}

// S3 edge: empty output is a clean, zero-findings success (not an error).
func TestKatanaExecute_EmptyOutputNoError(t *testing.T) {
	findings, err := collect(t, "empty", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// S4 edge: nonzero exit with no stdout is fatal; the error carries the stderr tail.
func TestKatanaExecute_NonZeroExitNoOutputIsError(t *testing.T) {
	findings, err := collect(t, "fail", "example.com")
	if err == nil {
		t.Fatal("expected error on nonzero exit with no output")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	msg := err.Error()
	if !contains(msg, "katana") {
		t.Errorf("error should mention katana, got: %s", msg)
	}
	if !contains(msg, "connection refused") {
		t.Errorf("error should carry the stderr tail, got: %s", msg)
	}
}

// S5 edge: nonzero exit WITH output is success (katana exit codes are unreliable).
func TestKatanaExecute_PartialOutputWithNonZeroExitSucceeds(t *testing.T) {
	findings, err := collect(t, "partial-fail", "example.com")
	if err != nil {
		t.Fatalf("partial output with nonzero exit must succeed, got %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

// S6 edge: runner init failure is detected from the stderr marker even though
// katana exits 0. This is katana-specific: the exit code is not the signal.
func TestKatanaExecute_RunnerInitFailureDetectedOnExitZero(t *testing.T) {
	findings, err := collect(t, "runner-fail", "example.com")
	if err == nil {
		t.Fatal("expected error when the runner init marker appears with zero output")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	if !contains(err.Error(), "could not create runner") {
		t.Fatalf("error should carry the runner init marker, got: %s", err.Error())
	}
}

// S7 edge: the maxUrls cap stops scanning, kills the process, keeps the
// partial findings and returns success.
func TestKatanaExecute_MaxUrlsCapKillsAndTruncates(t *testing.T) {
	bin := ensureFakeKatana(t)
	t.Setenv("KATANA_BIN", bin)
	t.Setenv("FAKE_MODE", "many")
	t.Setenv("OASM_CONFIG", `{"maxUrls":10}`)

	out := make(chan connector.Finding, 64)
	start := time.Now()
	err := KatanaAdapter{}.Execute(context.Background(), map[string]any{"target": "example.com"}, out)
	elapsed := time.Since(start)
	close(out)

	if err != nil {
		t.Fatalf("cap truncation must succeed, got %v", err)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("Execute took %s; the cap must kill the process, not wait for it", elapsed)
	}
	count := 0
	for range out {
		count++
	}
	if count != 10 {
		t.Fatalf("expected exactly 10 findings, got %d", count)
	}
}

// S8 edge: a wedged katana is killed by the parent context deadline.
func TestKatanaExecute_ContextTimeoutKillsProcess(t *testing.T) {
	bin := ensureFakeKatana(t)
	t.Setenv("KATANA_BIN", bin)
	t.Setenv("FAKE_MODE", "hang")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	out := make(chan connector.Finding, 64)
	start := time.Now()
	err := KatanaAdapter{}.Execute(ctx, map[string]any{"target": "example.com"}, out)
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

// S9 boundary: target normalization strips scheme/path/query/port.
func TestNormalizeTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com/a/b?x=1", "example.com"},
		{"example.com:443/x", "example.com"},
		{"   ", ""},
		{"http://EXAMPLE.com:8080", "EXAMPLE.com"},
		{"example.com", "example.com"},
		// userinfo and IPv6 literals must not be truncated at the first colon
		{"http://user:pw@example.com/x", "example.com"},
		{"https://[2001:db8::1]:8443/x", "2001:db8::1"},
		{"[::1]:8080", "::1"},
	}
	for _, tc := range cases {
		if got := normalizeTarget(tc.in); got != tc.want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// S9 boundary: Execute rejects a missing/blank target.
func TestKatanaExecute_MissingTargetErrors(t *testing.T) {
	for _, inputs := range []map[string]any{{}, {"target": "   "}} {
		out := make(chan connector.Finding, 64)
		err := KatanaAdapter{}.Execute(context.Background(), inputs, out)
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
