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
	fakeFfufPath string
	fakeFfufOnce sync.Once
)

// ensureFakeFfuf builds the fake ffuf binary once for the test run. Uses
// os.MkdirTemp (not t.TempDir) so the binary survives across tests and never
// lands in the repo.
func ensureFakeFfuf(t *testing.T) string {
	t.Helper()
	fakeFfufOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-ffuf-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeFfufPath = filepath.Join(dir, "fake-ffuf"+ext)
		cmd := exec.Command("go", "build", "-o", fakeFfufPath, "./testdata/fake-ffuf")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build fake-ffuf: %v\n%s", err, out)
		}
	})
	return fakeFfufPath
}

// collect runs Execute against the fake ffuf with FAKE_MODE=mode and returns the
// emitted findings plus the returned error.
func collect(t *testing.T, mode, target string) ([]connector.Finding, error) {
	t.Helper()
	bin := ensureFakeFfuf(t)
	t.Setenv("FFUF_BIN", bin)
	t.Setenv("FAKE_MODE", mode)

	out := make(chan connector.Finding, 64)
	err := FfufAdapter{}.Execute(context.Background(), map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

func TestValidate_IsNoOp(t *testing.T) {
	if err := (FfufAdapter{}).Validate(context.Background(), nil); err != nil {
		t.Fatalf("Validate should return nil, got %v", err)
	}
}

// happy: streams one Finding per unique URL, skipping duplicates/non-http/blanks.
func TestFfufExecute_StreamsUrlFindings(t *testing.T) {
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

// edge: empty output is a clean, zero-findings success (not an error).
func TestFfufExecute_EmptyOutputNoError(t *testing.T) {
	findings, err := collect(t, "empty", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// edge: nonzero exit with no stdout is fatal; the error carries the stderr tail.
func TestFfufExecute_NonZeroExitNoOutputIsError(t *testing.T) {
	findings, err := collect(t, "fail", "example.com")
	if err == nil {
		t.Fatal("expected error on nonzero exit with no output")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	msg := err.Error()
	if !contains(msg, "ffuf") {
		t.Errorf("error should mention ffuf, got: %s", msg)
	}
	if !contains(msg, "connection refused") {
		t.Errorf("error should carry the stderr tail, got: %s", msg)
	}
}

// edge: nonzero exit WITH output is success (ffuf exit codes are unreliable).
func TestFfufExecute_PartialOutputWithNonZeroExitSucceeds(t *testing.T) {
	findings, err := collect(t, "partial-fail", "example.com")
	if err != nil {
		t.Fatalf("partial output with nonzero exit must succeed, got %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

// edge: the maxUrls cap stops scanning, kills the process, keeps the partial
// findings and returns success.
func TestFfufExecute_MaxUrlsCapKillsAndTruncates(t *testing.T) {
	bin := ensureFakeFfuf(t)
	t.Setenv("FFUF_BIN", bin)
	t.Setenv("FAKE_MODE", "many")
	t.Setenv("OASM_CONFIG", `{"maxUrls":10}`)

	out := make(chan connector.Finding, 64)
	start := time.Now()
	err := FfufAdapter{}.Execute(context.Background(), map[string]any{"target": "example.com"}, out)
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

// edge: a wedged ffuf is killed by the parent context deadline.
func TestFfufExecute_ContextTimeoutKillsProcess(t *testing.T) {
	bin := ensureFakeFfuf(t)
	t.Setenv("FFUF_BIN", bin)
	t.Setenv("FAKE_MODE", "hang")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	out := make(chan connector.Finding, 64)
	start := time.Now()
	err := FfufAdapter{}.Execute(ctx, map[string]any{"target": "example.com"}, out)
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

// boundary: target normalization yields the base URL ffuf scans and the host
// attached to every finding.
func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct {
		in       string
		wantBase string
		wantHost string
		wantErr  bool
	}{
		{"https://example.com/a/b?x=1", "https://example.com/a/b", "example.com", false},
		{"example.com", "https://example.com", "example.com", false},
		{"example.com:443/x", "https://example.com:443/x", "example.com", false},
		{"http://EXAMPLE.com:8080", "http://EXAMPLE.com:8080", "EXAMPLE.com", false},
		{"https://example.com/", "https://example.com", "example.com", false},
		// userinfo and IPv6 literals resolve correctly.
		{"http://user:pw@example.com/x", "http://example.com/x", "example.com", false},
		{"https://[2001:db8::1]:8443/x", "https://[2001:db8::1]:8443/x", "2001:db8::1", false},
		{"", "", "", true},
		{"   ", "", "", true},
		{"-o", "", "", true},
		{"a,b", "", "", true},
		{"https://", "", "", true},
	}
	for _, tc := range cases {
		base, host, err := normalizeBaseURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeBaseURL(%q) expected error, got base=%q host=%q", tc.in, base, host)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeBaseURL(%q) unexpected error: %v", tc.in, err)
			continue
		}
		if base != tc.wantBase || host != tc.wantHost {
			t.Errorf("normalizeBaseURL(%q) = (%q, %q), want (%q, %q)", tc.in, base, host, tc.wantBase, tc.wantHost)
		}
	}
}

// boundary: Execute rejects a missing/blank target before spawning ffuf.
func TestFfufExecute_MissingTargetErrors(t *testing.T) {
	for _, inputs := range []map[string]any{{}, {"target": "   "}} {
		out := make(chan connector.Finding, 64)
		err := FfufAdapter{}.Execute(context.Background(), inputs, out)
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
