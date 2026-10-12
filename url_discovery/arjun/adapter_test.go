package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

var (
	fakeArjunPath string
	fakeArjunOnce sync.Once
)

// ensureFakeArjun builds the fake arjun binary once for the test run. Uses
// os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeArjun(t *testing.T) string {
	t.Helper()
	fakeArjunOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-arjun-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeArjunPath = filepath.Join(dir, "fake-arjun"+ext)
		cmd := exec.Command("go", "build", "-o", fakeArjunPath, "./testdata/fake-arjun")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build fake-arjun: %v\n%s", err, out)
		}
	})
	return fakeArjunPath
}

// collect runs Execute against the fake arjun with FAKE_MODE=mode and returns
// the emitted findings plus the returned error.
func collect(t *testing.T, mode, target string) ([]connector.Finding, error) {
	t.Helper()
	bin := ensureFakeArjun(t)
	t.Setenv("ARJUN_BIN", bin)
	t.Setenv("FAKE_MODE", mode)

	out := make(chan connector.Finding, 64)
	err := ArjunAdapter{}.Execute(context.Background(), map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

func TestValidate_IsNoOp(t *testing.T) {
	if err := (ArjunAdapter{}).Validate(context.Background(), nil); err != nil {
		t.Fatalf("Validate should return nil, got %v", err)
	}
}

// Happy path: one Finding per discovered parameter, named <url>?<param>.
func TestArjunExecute_StreamsParamFindings(t *testing.T) {
	findings, err := collect(t, "default", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d: %+v", len(findings), findings)
	}
	want := []string{
		"https://example.com/?id=",
		"https://example.com/?redirect=",
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

// A URL that already carries a query joins the next parameter with "&".
func TestParamName_Separator(t *testing.T) {
	if got := paramName("https://example.com/", "id"); got != "https://example.com/?id=" {
		t.Errorf("paramName without query = %q, want https://example.com/?id=", got)
	}
	if got := paramName("https://example.com/?a=1", "id"); got != "https://example.com/?a=1&id=" {
		t.Errorf("paramName with query = %q, want https://example.com/?a=1&id=", got)
	}
}

// The different-content marker is Arjun's own clean-empty result, NOT fatal.
func TestIsSkipMarker_DifferentContentIsClean(t *testing.T) {
	if isSkipMarker("Webpage is returning different content on each request. Skipping.") {
		t.Fatal("different-content marker must not be treated as a fatal skip")
	}
	for _, s := range []string{
		"target skipping due to errors",
		"URL doesn't seem to be a webpage. Skipping.",
		"https://x is not a valid URL",
	} {
		if !isSkipMarker(s) {
			t.Errorf("expected skip marker for %q", s)
		}
	}
}

// Empty output (no file) is a clean, zero-findings success (not an error).
func TestArjunExecute_EmptyOutputNoError(t *testing.T) {
	findings, err := collect(t, "empty", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// A refused target (skip marker, no findings) is fatal.
func TestArjunExecute_SkipMarkerIsFatal(t *testing.T) {
	findings, err := collect(t, "skip", "example.com")
	if err == nil {
		t.Fatal("expected fatal error for a skipped target")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	msg := err.Error()
	if !contains(msg, "target skipped") {
		t.Errorf("error should mention target skipped, got: %s", msg)
	}
	if !contains(msg, "doesn't seem to be a webpage") {
		t.Errorf("error should carry the skip marker, got: %s", msg)
	}
}

// Nonzero exit with no output is fatal; the error carries the stderr tail.
func TestArjunExecute_NonZeroExitNoOutputIsError(t *testing.T) {
	findings, err := collect(t, "fail", "example.com")
	if err == nil {
		t.Fatal("expected error on nonzero exit with no output")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	msg := err.Error()
	if !contains(msg, "arjun") {
		t.Errorf("error should mention arjun, got: %s", msg)
	}
	if !contains(msg, "AttributeError") {
		t.Errorf("error should carry the stderr tail, got: %s", msg)
	}
}

// The maxUrls cap stops emission at parse time, keeps partial findings and
// returns success.
func TestArjunExecute_MaxUrlsCapTruncates(t *testing.T) {
	bin := ensureFakeArjun(t)
	t.Setenv("ARJUN_BIN", bin)
	t.Setenv("FAKE_MODE", "many")
	t.Setenv("OASM_CONFIG", `{"maxUrls":10}`)

	out := make(chan connector.Finding, 64)
	err := ArjunAdapter{}.Execute(context.Background(), map[string]any{"target": "example.com"}, out)
	close(out)

	if err != nil {
		t.Fatalf("cap truncation must succeed, got %v", err)
	}
	count := 0
	for range out {
		count++
	}
	if count != 10 {
		t.Fatalf("expected exactly 10 findings, got %d", count)
	}
}

// A wedged arjun is killed by the parent context deadline.
func TestArjunExecute_ContextTimeoutKillsProcess(t *testing.T) {
	bin := ensureFakeArjun(t)
	t.Setenv("ARJUN_BIN", bin)
	t.Setenv("FAKE_MODE", "hang")

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	out := make(chan connector.Finding, 64)
	start := time.Now()
	err := ArjunAdapter{}.Execute(ctx, map[string]any{"target": "example.com"}, out)
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

// normalizeBaseURL validates the target and yields the -u base + bare host.
func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct {
		in, base, host string
		wantErr        bool
	}{
		{"https://example.com/a/b?x=1", "https://example.com/a/b?x=1", "example.com", false},
		{"http://example.com:8080", "http://example.com:8080", "example.com", false},
		{"example.com", "https://example.com", "example.com", false},
		{"example.com:443/x", "https://example.com:443/x", "example.com", false},
		{"   ", "", "", true},
		{"-x", "", "", true},
	}
	for _, tc := range cases {
		base, host, err := normalizeBaseURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeBaseURL(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeBaseURL(%q): unexpected error %v", tc.in, err)
			continue
		}
		if base != tc.base || host != tc.host {
			t.Errorf("normalizeBaseURL(%q) = (%q, %q), want (%q, %q)", tc.in, base, host, tc.base, tc.host)
		}
	}
}

// Execute rejects a missing/blank target before doing any work.
func TestArjunExecute_MissingTargetErrors(t *testing.T) {
	for _, inputs := range []map[string]any{{}, {"target": "   "}} {
		out := make(chan connector.Finding, 64)
		err := ArjunAdapter{}.Execute(context.Background(), inputs, out)
		close(out)
		if err == nil {
			t.Fatalf("expected error for inputs %+v", inputs)
		}
		if !contains(err.Error(), "arjun") {
			t.Fatalf("expected arjun-prefixed error, got: %s", err.Error())
		}
	}
}

// The adapter passes exactly buildArjunArgs(base, outFile, cfg) to the binary
// (via FAKE_ARGS_FILE), with -oJ pointing at an adapter-owned out.json.
func TestArjunExecute_PassesExpectedArgv(t *testing.T) {
	bin := ensureFakeArjun(t)
	argsFile := filepath.Join(t.TempDir(), "args.json")
	t.Setenv("ARJUN_BIN", bin)
	t.Setenv("FAKE_MODE", "default")
	t.Setenv("FAKE_ARGS_FILE", argsFile)
	t.Setenv("OASM_CONFIG", "")

	out := make(chan connector.Finding, 64)
	if err := (ArjunAdapter{}).Execute(context.Background(), map[string]any{"target": "https://example.com"}, out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	close(out)

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read args file: %v", err)
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatalf("unmarshal args: %v", err)
	}

	i := slices.Index(args, "-oJ")
	if i < 0 || i+1 >= len(args) {
		t.Fatalf("argv missing -oJ: %v", args)
	}
	outFile := args[i+1]
	if !strings.HasSuffix(outFile, "out.json") {
		t.Errorf("-oJ path = %q, want suffix out.json", outFile)
	}
	want := buildArjunArgs("https://example.com", outFile, &arjunConfig{})
	if !slices.Equal(args, want) {
		t.Errorf("argv:\n got %v\nwant %v", args, want)
	}
	// Explicit spot-checks called out by the connector contract.
	for _, tok := range []string{"-w", "medium", "-m", "GET", "-c", "250", "-T", "15", "--rate-limit", "9999"} {
		if !slices.Contains(args, tok) {
			t.Errorf("argv missing %q: %v", tok, args)
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
