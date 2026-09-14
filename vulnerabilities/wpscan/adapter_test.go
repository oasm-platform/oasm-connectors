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

// TestWpscanExecute_ScanAbortedIsNotFatal covers DEFECT A: a target-level
// scan_aborted (e.g. "does not seem to be running WordPress") is a permanent,
// non-retryable condition. It must NOT fail the job — Execute returns nil and
// emits zero findings. The reason is logged to stderr, not surfaced as an error.
func TestWpscanExecute_ScanAbortedIsNotFatal(t *testing.T) {
	findings, err := collect(t, "abort", "https://example.com")
	if err != nil {
		t.Fatalf("scan_aborted must be a non-fatal, zero-findings success, got error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}

// TestWpscanExecute_NotFullyConfiguredIsNotFatal covers the install-mode
// condition: not_fully_configured (the site is up but sitting at the install
// wizard) is a target-level, permanent, non-retryable state. Like scan_aborted
// it must NOT fail the job — Execute returns nil and emits zero findings. The
// reason is logged to stderr, not surfaced as an error.
func TestWpscanExecute_NotFullyConfiguredIsNotFatal(t *testing.T) {
	findings, err := collect(t, "notconfigured", "https://example.com")
	if err != nil {
		t.Fatalf("not_fully_configured must be a non-fatal, zero-findings success, got error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
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

// --- severity heuristic (no-CVSS) tests ---

func TestResolveSeverity_ScoreBandsUnaffected(t *testing.T) {
	v := wpscanVuln{Title: "Core RCE", CVSS: &wpscanCVSS{Score: json.RawMessage(`"0.0"`)}}
	sev, source := resolveSeverity(v)
	if sev != "info" || source != "" {
		t.Fatalf("got severity=%q source=%q, want info/\"\"", sev, source)
	}
}

func TestResolveSeverity_HeuristicTitleKeyword(t *testing.T) {
	cases := []struct{ title, want string }{
		{"Acme <= 1.2 - Remote Code Execution", "critical"},
		{"Acme <= 2.0 SQL Injection", "high"},
		{"Dignitas 1.1.9 - Privilage Escalation", "high"},
		{"Acme 1.0 - Stored XSS", "medium"},
		{"Acme 1.0 - Open Redirect", "low"},
		{"Some 1.0 - Unknown Issue", "info"},
	}
	for _, tc := range cases {
		sev, source := resolveSeverity(wpscanVuln{Title: tc.title})
		if sev != tc.want || source != "title" {
			t.Errorf("title %q: got severity=%q source=%q, want %q/title", tc.title, sev, source, tc.want)
		}
	}
}

func TestSeverityFromTitle_WordBoundaryTraps(t *testing.T) {
	for _, title := range []string{"Resource Cleanup <= 1.0", "Multisite Membership 1.0", "Dosage 1.0", "Source View 1.0"} {
		if sev, ok := severityFromTitle(title); ok {
			t.Errorf("title %q unexpectedly matched severity=%q", title, sev)
		}
	}
}

func TestResolveSeverity_UnparseableScoreUsesHeuristic(t *testing.T) {
	v := wpscanVuln{Title: "Acme 1.0 - Remote Code Execution", CVSS: &wpscanCVSS{Score: json.RawMessage(`"n/a"`)}}
	sev, source := resolveSeverity(v)
	if sev != "critical" || source != "title" {
		t.Fatalf("got severity=%q source=%q, want critical/title", sev, source)
	}
}

func TestResolveSeverity_FallbackUnknownTitle(t *testing.T) {
	sev, source := resolveSeverity(wpscanVuln{Title: "Weird Widget 1.0 - Glitch"})
	if sev != "medium" || source != "title-fallback" {
		t.Fatalf("got severity=%q source=%q, want medium/title-fallback", sev, source)
	}
}

func TestSeverityFromTitle_FullSpellingHigh(t *testing.T) {
	cases := []string{
		"Acme <= 1.0 - Local File Inclusion",
		"Acme <= 1.0 - Remote File Inclusion",
		"Acme <= 1.0 - Server-Side Request Forgery",
		"Acme <= 1.0 - XML External Entity",
	}
	for _, title := range cases {
		if sev, ok := severityFromTitle(title); !ok || sev != "high" {
			t.Errorf("title %q: got (%q,%v), want high/true", title, sev, ok)
		}
	}
}

func TestSeverityFromTitle_Redirection(t *testing.T) {
	for _, title := range []string{"Acme 1.0 - Open Redirect", "Acme 1.0 - Open Redirection"} {
		if sev, ok := severityFromTitle(title); !ok || sev != "low" {
			t.Errorf("title %q: got (%q,%v), want low/true", title, sev, ok)
		}
	}
}

func TestSeverityFromTitle_CodeExecution(t *testing.T) {
	for _, title := range []string{"Acme 1.0 - Arbitrary Code Execution", "Acme 1.0 - Command Execution"} {
		if sev, ok := severityFromTitle(title); !ok || sev != "critical" {
			t.Errorf("title %q: got (%q,%v), want critical/true", title, sev, ok)
		}
	}
}

func TestSeverityFromTitle_Precedence(t *testing.T) {
	cases := []struct{ title, want string }{
		{"Acme 1.0 - Command Injection", "critical"},
		{"Acme 1.0 - PHP Object Injection", "high"},
		{"Acme 1.0 - Authentication Bypass", "high"},
		{"Acme 1.0 - SQL Injection", "high"},
	}
	for _, tc := range cases {
		if sev, ok := severityFromTitle(tc.title); !ok || sev != tc.want {
			t.Errorf("title %q: got (%q,%v), want %q/true", tc.title, sev, ok, tc.want)
		}
	}
}

func TestResolveSeverity_UnparseableScoreWithVector(t *testing.T) {
	v := wpscanVuln{Title: "Acme 1.0 - Remote Code Execution", CVSS: &wpscanCVSS{Score: json.RawMessage(`"n/a"`), Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	sev, source := resolveSeverity(v)
	if sev != "critical" || source != "title" {
		t.Fatalf("got (%q,%q), want critical/title", sev, source)
	}
	f, ok := toFinding(v, "https://example.com")
	if !ok {
		t.Fatal("toFinding returned ok=false")
	}
	if f.CVSSScore != 0 || f.CVSSMetrics != "" {
		t.Errorf("unparseable score must not set CVSS fields, got score=%v metrics=%q", f.CVSSScore, f.CVSSMetrics)
	}
}

func TestToFinding_SkipsEmptyTitle(t *testing.T) {
	if _, ok := toFinding(wpscanVuln{Title: "   "}, "https://example.com"); ok {
		t.Fatal("blank title should be skipped")
	}
}

func TestWpscanExecute_HeuristicSeverityWithoutCVSS(t *testing.T) {
	findings, err := collect(t, "nocvss", "https://example.com")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	want := map[string]string{
		"Acme <= 1.2 - Remote Code Execution": "critical",
		"Acme <= 2.0 SQL Injection":           "high",
		"Acme 1.0 - Stored XSS":               "medium",
		"Acme 1.0 - Open Redirect":            "low",
		"Acme 1.0 - Unspecified Glitch":       "medium",
		"Acme 1.0 - Authentication Bypass":    "high",
		"Acme Scored RCE":                     "critical",
	}
	if len(findings) != len(want) {
		t.Fatalf("got %d findings, want %d: %+v", len(findings), len(want), findings)
	}
	for _, f := range findings {
		expected, ok := want[f.Name]
		if !ok {
			t.Fatalf("unexpected finding %q", f.Name)
		}
		if f.Severity != expected {
			t.Errorf("finding %q: severity=%q, want %q", f.Name, f.Severity, expected)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("finding %q failed Validate: %v", f.Name, err)
		}
		if f.Name == "Acme Scored RCE" {
			if f.CVSSScore != 9.8 {
				t.Errorf("scored finding CVSSScore=%v, want 9.8", f.CVSSScore)
			}
			if f.CVSSMetrics == "" {
				t.Error("scored finding CVSSMetrics should carry the vector")
			}
			if len(f.Tags) != 0 {
				t.Errorf("scored finding should have no heuristic tags, got %v", f.Tags)
			}
			continue
		}
		if f.CVSSScore != 0 {
			t.Errorf("heuristic finding %q should not have CVSSScore, got %v", f.Name, f.CVSSScore)
		}
		if f.CVSSMetrics != "" {
			t.Errorf("heuristic finding %q should not have CVSSMetrics, got %q", f.Name, f.CVSSMetrics)
		}
		if !slices.Contains(f.Tags, "severity:heuristic") {
			t.Errorf("heuristic finding %q missing severity:heuristic tag: %v", f.Name, f.Tags)
		}
		if f.Name == "Acme 1.0 - Unspecified Glitch" {
			if !slices.Contains(f.Tags, "severity-source:title-fallback") {
				t.Errorf("fallback finding %q missing severity-source:title-fallback: %v", f.Name, f.Tags)
			}
			continue
		}
		if !slices.Contains(f.Tags, "severity-source:title") {
			t.Errorf("heuristic finding %q missing severity-source:title: %v", f.Name, f.Tags)
		}
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
