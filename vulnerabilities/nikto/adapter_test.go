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
	fakeNiktoPath string
	fakeOnce      sync.Once
)

// ensureFakeNikto builds the fake nikto binary once per test run. Uses
// os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeNikto(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-nikto-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeNiktoPath = filepath.Join(dir, "fake-nikto"+ext)
		cmd := exec.Command("go", "build", "-o", fakeNiktoPath, "./testdata/fake-nikto")
		cmd.Dir = "."
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build fake-nikto: %v\n%s", err, out)
		}
	})
	return fakeNiktoPath
}

// assertOnlyCategoryTags enforces the Tags contract: the array carries the
// check class and nothing else, because Core's summary report renders tags[0]
// as the finding's category (see summary-report.service.ts).
func assertOnlyCategoryTags(t *testing.T, f connector.Finding) {
	t.Helper()
	for _, tag := range f.Tags {
		if !strings.HasPrefix(tag, "category:") {
			t.Errorf("finding %q: non-category tag %q in %v", f.Name, tag, f.Tags)
		}
	}
}

// collect runs Execute against the fake nikto with FAKE_MODE=mode and returns
// the emitted findings plus the returned error.
func collect(t *testing.T, mode, target string) ([]connector.Finding, error) {
	t.Helper()
	bin := ensureFakeNikto(t)
	t.Setenv("NIKTO_BIN", bin)
	t.Setenv("FAKE_MODE", mode)

	out := make(chan connector.Finding, 64)
	err := NiktoAdapter{}.Execute(context.Background(), map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

func TestValidate_IsNoOp(t *testing.T) {
	if err := (NiktoAdapter{}).Validate(context.Background(), nil); err != nil {
		t.Fatalf("Validate should return nil, got %v", err)
	}
}

func TestNiktoExecute_MissingTargetErrors(t *testing.T) {
	for _, inputs := range []map[string]any{{}, {"target": "   "}} {
		out := make(chan connector.Finding, 8)
		err := NiktoAdapter{}.Execute(context.Background(), inputs, out)
		close(out)
		if err == nil {
			t.Fatalf("inputs %v: expected error", inputs)
		}
		if !contains(err.Error(), "target required") {
			t.Fatalf("inputs %v: expected 'target required', got: %s", inputs, err.Error())
		}
	}
}

// TestNiktoExecute_StreamsFindings covers the happy path: only the three
// "+ [id] msg" result lines become findings — the banner, the "+ Target ..."
// header lines, "+ Server: ..." and the closing "+ N host(s) tested" do not.
func TestNiktoExecute_StreamsFindings(t *testing.T) {
	findings, err := collect(t, "default", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		names := make([]string, len(findings))
		for i, f := range findings {
			names[i] = f.Name
		}
		t.Fatalf("expected 3 findings, got %d: %v", len(findings), names)
	}

	first := findings[0]
	if first.Name != "Attackers may be able to crash FrontPage by requesting a DOS device." {
		t.Errorf("unexpected first finding name: %q", first.Name)
	}
	// The affected path nikto prefixes to the message becomes the absolute URL.
	if first.MatchedAt != "https://example.com/_vti_bin/shtml.exe" {
		t.Errorf("MatchedAt = %q, want the resolved item URL", first.MatchedAt)
	}
	if first.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", first.Host)
	}
	// Tags carry the check class only: Core's summary report renders tags[0] as
	// the finding's category, so the nikto test id must not appear there.
	assertOnlyCategoryTags(t, first)
	if !slices.Equal(first.CVEID, []string{"CVE-2000-0709"}) {
		t.Errorf("CVEID = %v, want [CVE-2000-0709]", first.CVEID)
	}
	if slices.Contains(first.References, "See:") {
		t.Errorf("reference split leaked the 'See:' separator: %v", first.References)
	}
	if findings[1].MatchedAt != "https://example.com/admin/" {
		t.Errorf("second MatchedAt = %q, want https://example.com/admin/", findings[1].MatchedAt)
	}

	// The third item carries both a bare CVE and a full advisory URL.
	third := findings[2]
	if !slices.Contains(third.CVEID, "CVE-2001-1013") {
		t.Errorf("third finding CVEID = %v, want CVE-2001-1013", third.CVEID)
	}
	if !slices.Contains(third.References, "https://nvd.nist.gov/vuln/detail/CVE-2001-1013") {
		t.Errorf("third finding references = %v, want the advisory URL", third.References)
	}

	for i, f := range findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d invalid: %v", i, err)
		}
	}
}

func TestNiktoExecute_EmptyOutputNoError(t *testing.T) {
	findings, err := collect(t, "empty", "https://clean.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// TestNiktoExecute_UnreachableTargetIsNotAFinding covers the "+ [FAIL] Unable
// to connect ..." pseudo-item: it must not be persisted as a vulnerability.
func TestNiktoExecute_UnreachableTargetIsNotAFinding(t *testing.T) {
	findings, err := collect(t, "unreachable", "https://down.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("connect failure must not become a finding, got %d: %+v", len(findings), findings)
	}
}

func TestNiktoExecute_NonZeroExitNoOutputIsError(t *testing.T) {
	_, err := collect(t, "fail", "https://example.com")
	if err == nil {
		t.Fatal("expected error when nikto exits nonzero with no results")
	}
	if !contains(err.Error(), "db_tests") {
		t.Fatalf("expected stderr tail in error, got: %s", err.Error())
	}
}

// TestNiktoExecute_PartialOutputWithNonZeroExitSucceeds pins the policy that a
// parseable stdout wins over a nonzero exit.
func TestNiktoExecute_PartialOutputWithNonZeroExitSucceeds(t *testing.T) {
	findings, err := collect(t, "partial-fail", "https://example.com")
	if err != nil {
		t.Fatalf("nonzero exit with results must succeed, got: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}
}

func TestNiktoExecute_ContextCancelKillsProcess(t *testing.T) {
	bin := ensureFakeNikto(t)
	t.Setenv("NIKTO_BIN", bin)
	t.Setenv("FAKE_MODE", "hang")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Give the process time to start, then cancel.
		<-time.After(300 * time.Millisecond)
		cancel()
	}()

	out := make(chan connector.Finding, 8)
	start := time.Now()
	err := NiktoAdapter{}.Execute(ctx, map[string]any{"target": "https://example.com"}, out)
	close(out)
	if err == nil {
		t.Fatal("expected error on context cancel")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("cancel did not kill the process promptly: %s", elapsed)
	}
}

// TestNiktoExecute_NormalizesBareTarget proves a bare host is upgraded to a URL
// and that a non-default port survives (unlike the crawler connectors, which
// strip it).
func TestNiktoExecute_NormalizesBareTarget(t *testing.T) {
	args := captureArgs(t, "")
	if !slices.Contains(args, "https://example.com") {
		t.Fatalf("bare target not normalized: %v", args)
	}

	args = captureArgsFor(t, "", "example.com:8443")
	if !slices.Contains(args, "https://example.com:8443") {
		t.Fatalf("port must survive normalization: %v", args)
	}
}

// captureArgs runs Execute with cfgJSON in OASM_CONFIG and returns the argv
// vector the fake nikto received.
func captureArgs(t *testing.T, cfgJSON string) []string {
	return captureArgsFor(t, cfgJSON, "example.com")
}

func captureArgsFor(t *testing.T, cfgJSON, target string) []string {
	t.Helper()
	bin := ensureFakeNikto(t)
	t.Setenv("NIKTO_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", cfgJSON)

	argsFile := filepath.Join(t.TempDir(), "args.json")
	t.Setenv("FAKE_ARGS_FILE", argsFile)

	out := make(chan connector.Finding, 64)
	if err := (NiktoAdapter{}).Execute(context.Background(), map[string]any{"target": target}, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatalf("decode captured args: %v", err)
	}
	return args
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
