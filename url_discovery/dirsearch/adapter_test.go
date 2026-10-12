package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

var (
	fakeDirsearchPath string
	fakeDirsearchOnce sync.Once
)

// ensureFakeDirsearch builds the fake dirsearch binary once for the test run.
// Uses os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeDirsearch(t *testing.T) string {
	t.Helper()
	fakeDirsearchOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-dirsearch-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeDirsearchPath = filepath.Join(dir, "fake-dirsearch"+ext)
		cmd := exec.Command("go", "build", "-o", fakeDirsearchPath, "./testdata/fake-dirsearch")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build fake-dirsearch: %v\n%s", err, out)
		}
	})
	return fakeDirsearchPath
}

// writeDummyWordlist creates a DIRSEARCH_WORDLIST_DIR containing the dicc.txt
// the adapter resolves by default, and points the env at it.
func writeDummyWordlist(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dicc.txt"), []byte("admin\n"), 0644); err != nil {
		t.Fatalf("write dummy wordlist: %v", err)
	}
	t.Setenv("DIRSEARCH_WORDLIST_DIR", dir)
}

// runCollect runs Execute against the fake dirsearch with FAKE_MODE=mode and
// OASM_CONFIG=cfgJSON, returning the emitted findings plus the returned error.
func runCollect(t *testing.T, mode, target, cfgJSON string) ([]connector.Finding, error) {
	t.Helper()
	bin := ensureFakeDirsearch(t)
	t.Setenv("DIRSEARCH_BIN", bin)
	t.Setenv("FAKE_MODE", mode)
	t.Setenv("OASM_CONFIG", cfgJSON)
	writeDummyWordlist(t)

	out := make(chan connector.Finding, 64)
	err := DirsearchAdapter{}.Execute(context.Background(), map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

func collect(t *testing.T, mode, target string) ([]connector.Finding, error) {
	return runCollect(t, mode, target, "")
}

func TestValidate_IsNoOp(t *testing.T) {
	if err := (DirsearchAdapter{}).Validate(context.Background(), nil); err != nil {
		t.Fatalf("Validate should return nil, got %v", err)
	}
}

// C1 happy: streams one Finding per unique URL parsed from the JSON report,
// skipping the duplicate entry.
func TestDirsearchExecute_StreamsUrlFindings(t *testing.T) {
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

// C2 edge: a present report with an empty results array is a clean,
// zero-findings success (not an error).
func TestDirsearchExecute_EmptyResultsNoError(t *testing.T) {
	findings, err := collect(t, "empty", "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// C3 edge: nonzero exit with no report file is fatal; the error carries
// dirsearch and the stderr tail.
func TestDirsearchExecute_NonZeroExitNoReportIsError(t *testing.T) {
	findings, err := collect(t, "fail", "example.com")
	if err == nil {
		t.Fatal("expected error on nonzero exit with no report")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	msg := err.Error()
	if !contains(msg, "dirsearch") {
		t.Errorf("error should mention dirsearch, got: %s", msg)
	}
	if !contains(msg, "connection refused") {
		t.Errorf("error should carry the stderr tail, got: %s", msg)
	}
}

// C4 edge: nonzero exit WITH report data is success (partial results useful).
func TestDirsearchExecute_PartialReportWithNonZeroExitSucceeds(t *testing.T) {
	findings, err := collect(t, "partial-fail", "example.com")
	if err != nil {
		t.Fatalf("partial report with nonzero exit must succeed, got %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

// C5 boundary: maxUrls caps the emitted findings at parse time.
func TestDirsearchExecute_MaxUrlsCapTruncates(t *testing.T) {
	findings, err := runCollect(t, "many", "example.com", `{"maxUrls":10}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 10 {
		t.Fatalf("expected 10 findings (cap), got %d", len(findings))
	}
}

// C6 edge: a wedged dirsearch is killed by the parent context deadline.
func TestDirsearchExecute_ContextTimeoutKillsProcess(t *testing.T) {
	bin := ensureFakeDirsearch(t)
	t.Setenv("DIRSEARCH_BIN", bin)
	t.Setenv("FAKE_MODE", "hang")
	t.Setenv("OASM_CONFIG", "")
	writeDummyWordlist(t)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	out := make(chan connector.Finding, 64)
	start := time.Now()
	err := DirsearchAdapter{}.Execute(ctx, map[string]any{"target": "example.com"}, out)
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

// C7 boundary: target normalization builds the base URL and bare host.
func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct {
		in       string
		wantBase string
		wantHost string
		wantErr  bool
	}{
		{"https://example.com/a/b?x=1", "https://example.com/a/b", "example.com", false},
		{"example.com/path", "https://example.com/path", "example.com", false},
		{"http://example.com:8080", "http://example.com:8080", "example.com", false},
		{"https://example.com/", "https://example.com", "example.com", false},
		{"", "", "", true},
		{"   ", "", "", true},
		{"-bad", "", "", true},
		{"http://ex.com/a,b", "", "", true},
		{"https://", "", "", true},
	}
	for _, tc := range cases {
		base, host, err := normalizeBaseURL(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("normalizeBaseURL(%q): expected error, got (%q, %q)", tc.in, base, host)
			}
			continue
		}
		if err != nil {
			t.Errorf("normalizeBaseURL(%q): unexpected error %v", tc.in, err)
			continue
		}
		if base != tc.wantBase || host != tc.wantHost {
			t.Errorf("normalizeBaseURL(%q) = (%q, %q), want (%q, %q)", tc.in, base, host, tc.wantBase, tc.wantHost)
		}
	}
}

// C8 args: the argv actually handed to the dirsearch binary (captured by the
// fake) matches buildDirsearchArgs, proving Execute wires OASM_CONFIG -> CLI.
// The output path is a per-run temp file, so it is checked for shape rather
// than exact equality.
func TestDirsearchExecute_PassesBuiltArgsToBinary(t *testing.T) {
	bin := ensureFakeDirsearch(t)
	argsFile := filepath.Join(t.TempDir(), "args.json")
	wlDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wlDir, "dicc.txt"), []byte("admin\n"), 0644); err != nil {
		t.Fatalf("write dummy wordlist: %v", err)
	}

	t.Setenv("DIRSEARCH_BIN", bin)
	t.Setenv("FAKE_MODE", "default")
	t.Setenv("FAKE_ARGS_FILE", argsFile)
	t.Setenv("DIRSEARCH_WORDLIST_DIR", wlDir)
	t.Setenv("OASM_CONFIG", `{"threads":7,"extensions":["php"],"recursive":true,"maxRecursionDepth":2,`+
		`"method":"GET","maxUrls":100}`)

	out := make(chan connector.Finding, 64)
	err := DirsearchAdapter{}.Execute(context.Background(), map[string]any{"target": "https://example.com/x"}, out)
	close(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for range out {
	}

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	var got []string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal captured args: %v", err)
	}

	// The -o value is a random temp path; assert its shape, then blank it for
	// the exact-vector comparison below.
	var outPath string
	for i := 0; i+1 < len(got); i++ {
		if got[i] == "-o" {
			outPath = got[i+1]
			got[i+1] = "<OUT>"
		}
	}
	if !contains(outPath, "report.json") {
		t.Errorf("output path %q should point at report.json", outPath)
	}

	want := []string{
		"-u", "https://example.com/x",
		"-O", "json",
		"-o", "<OUT>",
		"-q",
		"--no-color",
		"-w", filepath.Join(wlDir, "dicc.txt"),
		"-e", "php",
		"-t", "7",
		"-r",
		"-R", "2",
		"-m", "GET",
	}
	if !slices.Equal(got, want) {
		t.Errorf("captured argv:\n got %v\nwant %v", got, want)
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
