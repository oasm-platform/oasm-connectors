package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

var (
	fakeWpscanPath string
	fakeOnce       sync.Once
)

// ensureFakeWpscan builds the fake wpscan binary once for the test run.
// Uses os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeWpscan(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-wpscan-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeWpscanPath = filepath.Join(dir, "fake-wpscan"+ext)
		cmd := exec.Command("go", "build", "-o", fakeWpscanPath, "./testdata/fake-wpscan")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build fake-wpscan: %v\n%s", err, out)
		}
	})
	return fakeWpscanPath
}

func TestValidate_IsNoOp(t *testing.T) {
	a := WpscanAdapter{}
	if err := a.Validate(context.Background(), nil); err != nil {
		t.Fatalf("Validate should return nil, got %v", err)
	}
}

func TestWpscanExecute_MissingTargetErrors(t *testing.T) {
	a := WpscanAdapter{}
	out := make(chan connector.Finding, 64)
	err := a.Execute(context.Background(), map[string]any{}, out)
	close(out)
	if err == nil {
		t.Fatal("expected error for missing target")
	}
	if !contains(err.Error(), "target required") {
		t.Fatalf("expected 'target required' in error, got: %s", err.Error())
	}
}

func TestWpscanExecute_StreamsJsonlFindings(t *testing.T) {
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)

	a := WpscanAdapter{}
	out := make(chan connector.Finding, 64)
	ctx := context.Background()

	err := a.Execute(ctx, map[string]any{"target": "https://example.com"}, out)
	close(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check first finding (core vulnerability).
	if findings[0].Name != "XSS in Search Form" {
		t.Errorf("expected first finding name 'XSS in Search Form', got %q", findings[0].Name)
	}
	if findings[0].MatchedAt != "https://example.com" {
		t.Errorf("expected first finding MatchedAt 'https://example.com', got %q", findings[0].MatchedAt)
	}

	// Check second finding (plugin vulnerability).
	if findings[1].Name != "Open Redirect in Akismet" {
		t.Errorf("expected second finding name 'Open Redirect in Akismet', got %q", findings[1].Name)
	}

	// Every emitted Finding must pass the SDK contract validation.
	for i, f := range findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d invalid: %v", i, err)
		}
	}
}

func TestWpscanExecute_EmptyOutputNoError(t *testing.T) {
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")

	a := WpscanAdapter{}
	out := make(chan connector.Finding, 64)
	ctx := context.Background()

	err := a.Execute(ctx, map[string]any{"target": "https://clean.example.com"}, out)
	close(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for range out {
		count++
	}
	if count != 0 {
		t.Fatalf("expected 0 findings, got %d", count)
	}
}

func TestWpscanExecute_ReturnsErrorOnNonZeroExit(t *testing.T) {
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)
	t.Setenv("FAKE_MODE", "fail")

	a := WpscanAdapter{}
	out := make(chan connector.Finding, 64)
	ctx := context.Background()

	err := a.Execute(ctx, map[string]any{"target": "https://example.com"}, out)
	close(out)
	if err == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !contains(err.Error(), "connection refused") {
		t.Fatalf("expected 'connection refused' in error, got: %s", err.Error())
	}
}

// --- DEFECT A/B regression tests (added for the exit-code + schema bugfix) ---

// collect runs Execute against the fake wpscan with FAKE_MODE=mode and returns
// the emitted findings plus the returned error.
func collect(t *testing.T, mode, target string) ([]connector.Finding, error) {
	t.Helper()
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)
	t.Setenv("FAKE_MODE", mode)

	out := make(chan connector.Finding, 64)
	err := WpscanAdapter{}.Execute(context.Background(), map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

// TestWpscanExecute_ScanAbortedSurfacesReason covers DEFECT A: exit 4 with a
// scan_aborted payload must surface the reason, not a bare "exit status 4".
func TestWpscanExecute_ScanAbortedSurfacesReason(t *testing.T) {
	findings, err := collect(t, "abort", "https://example.com")
	if err == nil {
		t.Fatal("expected error for aborted scan")
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
	if !contains(err.Error(), "scan aborted") {
		t.Fatalf("expected 'scan aborted' in error, got: %s", err.Error())
	}
	if !contains(err.Error(), "does not seem to be running WordPress") {
		t.Fatalf("expected abort reason in error, got: %s", err.Error())
	}
	if contains(err.Error(), "exit status 4") {
		t.Fatalf("error must not be a bare exit status, got: %s", err.Error())
	}
}

// TestWpscanExecute_NotFullyConfigured covers DEFECT A install mode.
func TestWpscanExecute_NotFullyConfigured(t *testing.T) {
	_, err := collect(t, "notconfigured", "https://example.com")
	if err == nil {
		t.Fatal("expected error for not-fully-configured scan")
	}
	if !contains(err.Error(), "not fully configured") && !contains(err.Error(), "install mode") {
		t.Fatalf("expected configuration reason in error, got: %s", err.Error())
	}
}

// TestWpscanExecute_Exit5WithVulnsSucceeds covers DEFECT A: exit 5 is success.
func TestWpscanExecute_Exit5WithVulnsSucceeds(t *testing.T) {
	findings, err := collect(t, "vuln5", "https://example.com")
	if err != nil {
		t.Fatalf("exit 5 must be treated as success, got error: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from exit 5 scan")
	}
	for i, f := range findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d invalid: %v", i, err)
		}
	}
}

// TestWpscanExecute_ParsesAllVulnerabilityLocations covers DEFECT B: exactly one
// vuln at each of the 7 real locations => 7 findings.
func TestWpscanExecute_ParsesAllVulnerabilityLocations(t *testing.T) {
	findings, err := collect(t, "all", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 7 {
		names := make([]string, len(findings))
		for i, f := range findings {
			names[i] = f.Name
		}
		t.Fatalf("expected 7 findings (one per location), got %d: %v", len(findings), names)
	}
	want := map[string]bool{
		"Loc1 Core":             true,
		"Loc2 Plugin":           true,
		"Loc3 PluginVersion":    true,
		"Loc4 Theme":            true,
		"Loc5 ThemeVersion":     true,
		"Loc6 MainTheme":        true,
		"Loc7 MainThemeVersion": true,
	}
	for _, f := range findings {
		if !want[f.Name] {
			t.Errorf("unexpected finding name %q", f.Name)
		}
		delete(want, f.Name)
	}
	for name := range want {
		t.Errorf("missing location %q", name)
	}
}

// TestWpscanExecute_RejectsNonJsonNonzeroExit covers DEFECT A: unparseable
// stdout + nonzero exit => error carrying exit code and stderr tail.
func TestWpscanExecute_RejectsNonJsonNonzeroExit(t *testing.T) {
	_, err := collect(t, "garbage", "https://example.com")
	if err == nil {
		t.Fatal("expected error for non-JSON stdout with nonzero exit")
	}
	if !contains(err.Error(), "exit status 1") {
		t.Fatalf("expected exit code in error, got: %s", err.Error())
	}
	if !contains(err.Error(), "unknown option --bogus") {
		t.Fatalf("expected stderr tail in error, got: %s", err.Error())
	}
}

// TestDeriveSeverity_FromCVSS covers the CVSS-band mapping, parsing the score
// whether it is a JSON string or a number, and absent/unparseable => info.
func TestDeriveSeverity_FromCVSS(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{"string score", `"7.5"`, "high"},
		{"number score", `7.5`, "high"},
		{"critical boundary 9.0", `9.0`, "critical"},
		{"high boundary 8.9", `8.9`, "high"},
		{"high boundary 7.0", `7.0`, "high"},
		{"medium boundary 6.9", `6.9`, "medium"},
		{"medium boundary 4.0", `4.0`, "medium"},
		{"low boundary 3.9", `3.9`, "low"},
		{"low boundary 0.1", `0.1`, "low"},
		{"zero score", `0.0`, "info"},
		{"absent null", `null`, "info"},
		{"empty string", `""`, "info"},
		{"unparseable", `"n/a"`, "info"},
		{"missing", ``, "info"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var raw json.RawMessage
			if tt.raw != "" {
				raw = json.RawMessage(tt.raw)
			}
			if got := severityFromRawScore(raw); got != tt.want {
				t.Errorf("severityFromRawScore(%s) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

// TestWpscanExecute_MapsCvssAndSolution covers the DEFECT B finding mapping:
// Name/Severity/CVSSScore/CVSSMetrics.
func TestWpscanExecute_MapsCvssAndSolution(t *testing.T) {
	findings, err := collect(t, "vuln5", "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	byName := map[string]connector.Finding{}
	for _, f := range findings {
		byName[f.Name] = f
	}

	core, ok := byName["Core RCE"]
	if !ok {
		t.Fatalf("missing core finding; got %v", byName)
	}
	if core.Severity != "critical" {
		t.Errorf("Core RCE severity = %q, want critical", core.Severity)
	}
	if core.CVSSScore != 9.8 {
		t.Errorf("Core RCE CVSSScore = %v, want 9.8", core.CVSSScore)
	}
	if core.CVSSMetrics == "" {
		t.Error("Core RCE CVSSMetrics should carry the vector")
	}

	plugin, ok := byName["CF7 Stored XSS"]
	if !ok {
		t.Fatalf("missing plugin finding; got %v", byName)
	}
	if plugin.Severity != "medium" {
		t.Errorf("plugin severity = %q, want medium (6.1)", plugin.Severity)
	}
	if plugin.CVSSScore != 6.1 {
		t.Errorf("plugin CVSSScore = %v, want 6.1", plugin.CVSSScore)
	}

	theme, ok := byName["Theme File Inclusion"]
	if !ok {
		t.Fatalf("missing main_theme finding; got %v", byName)
	}
	if theme.Severity != "high" {
		t.Errorf("theme severity = %q, want high (8.1)", theme.Severity)
	}
}

// TestRealFixture_ParsesCapturedScan parses the captured real WP 5.4.2 scan
// (exit 0, no API token) through the structs and asserts key fields. Skips when
// the fixture is absent so the suite stays portable.
func TestRealFixture_ParsesCapturedScan(t *testing.T) {
	const path = `C:/Users/l1ttp/AppData/Local/Temp/opencode/vuln2.json`
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("real fixture not available: %v", err)
	}
	var parsed wpscanOutput
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("unmarshal real fixture: %v", err)
	}
	if parsed.TargetURL == "" {
		t.Fatalf("target_url not parsed from real fixture: %+v", parsed)
	}
	if parsed.Version == nil || parsed.Version.Number != "5.4.2" {
		t.Fatalf("core version not parsed: %+v", parsed.Version)
	}
	if parsed.ScanAborted != "" {
		t.Fatalf("unexpected scan_aborted: %q", parsed.ScanAborted)
	}
}

// --- helpers ---

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
