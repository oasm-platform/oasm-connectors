package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
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
		fakeBinPath = filepath.Join(dir, "fake-nuclei")
		if runtime.GOOS == "windows" {
			fakeBinPath += ".exe"
		}
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
	ch := make(chan connector.Finding, 4)
	err := a.Execute(context.Background(), map[string]any{}, ch)
	if err == nil {
		t.Fatal("expected error for missing target")
	}
	if got := err.Error(); !strings.Contains(got, "target required") {
		t.Fatalf("want 'target required', got: %v", got)
	}
	select {
	case b := <-ch:
		t.Fatalf("nothing should be emitted, got: %+v", b)
	default:
	}
}

// TestNucleiExecute_StreamsJsonlFindings is the happy path: JSONL findings are
// streamed through, banner/noise lines are skipped.
func TestNucleiExecute_StreamsJsonlFindings(t *testing.T) {
	t.Setenv("NUCLEI_BIN", ensureFakeNuclei(t))
	t.Setenv("NUCLEI_TEMPLATE_DIR", setupTemplateDir(t))
	a := &NucleiAdapter{}
	ch := make(chan connector.Finding, 8)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	close(ch)
	var findings []connector.Finding
	for f := range ch {
		findings = append(findings, f)
	}
	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 findings (noise skipped), got %d", len(findings))
	}
	wantNames := []string{"Example CVE 2023", "Example CVE 2024"}
	for i, name := range wantNames {
		if findings[i].Name != name {
			t.Errorf("finding[%d].Name = %q, want %q", i, findings[i].Name, name)
		}
	}
	if findings[0].Severity != "high" || findings[1].Severity != "medium" {
		t.Errorf("severities = %q/%q, want high/medium", findings[0].Severity, findings[1].Severity)
	}
	if findings[0].MatchedAt != "https://example.com" {
		t.Errorf("matched-at mismatch: %q", findings[0].MatchedAt)
	}
	if err := findings[0].Validate(); err != nil {
		t.Errorf("emitted finding must validate, got: %v", err)
	}
}

// TestNucleiExecute_EmptyOutputNoError: exit 0 with no output -> no error, no emission.
func TestNucleiExecute_EmptyOutputNoError(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("NUCLEI_TEMPLATE_DIR", setupTemplateDir(t))
	t.Setenv("FAKE_MODE", "empty")
	a := &NucleiAdapter{}
	ch := make(chan connector.Finding, 4)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("expected nil error for empty output, got: %v", err)
	}
	select {
	case b := <-ch:
		t.Fatalf("nothing should be emitted, got: %+v", b)
	default:
	}
}

// TestNucleiExecute_ReturnsErrorOnNonZeroExit: non-zero exit surfaces stderr.
func TestNucleiExecute_ReturnsErrorOnNonZeroExit(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("NUCLEI_TEMPLATE_DIR", setupTemplateDir(t))
	t.Setenv("FAKE_MODE", "fail")
	a := &NucleiAdapter{}
	ch := make(chan connector.Finding, 4)
	err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch)
	if err == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if got := err.Error(); !strings.Contains(got, "connection refused") {
		t.Fatalf("error should contain stderr fragment, got: %v", got)
	}
}

// ---------------------------------------------------------------------------
// buildCLIArgs — table-driven tests for params → CLI flag mapping
// ---------------------------------------------------------------------------

func TestBuildCLIArgs(t *testing.T) {
	target := "https://example.com"

	tests := []struct {
		name   string
		cfg    Config
		expect []string
	}{
		{
			name:   "empty config yields stable flags and manifest defaults",
			cfg:    Config{},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-rl", "150", "-c", "25", "-target", target, "-jsonl"},
		},
		{
			name:   "severity single",
			cfg:    Config{Severity: []string{"high"}},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-severity", "high", "-rl", "150", "-c", "25", "-target", target, "-jsonl"},
		},
		{
			name:   "severity multiple csv",
			cfg:    Config{Severity: []string{"high", "critical"}},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-severity", "high,critical", "-rl", "150", "-c", "25", "-target", target, "-jsonl"},
		},
		{
			name:   "tags csv",
			cfg:    Config{Tags: []string{"cve", "xss"}},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-tags", "cve,xss", "-rl", "150", "-c", "25", "-target", target, "-jsonl"},
		},
		{
			name:   "excludeTags csv",
			cfg:    Config{ExcludeTags: []string{"dos"}},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-etags", "dos", "-rl", "150", "-c", "25", "-target", target, "-jsonl"},
		},
		{
			name:   "templateIds csv",
			cfg:    Config{TemplateIds: []string{"CVE-2021-1234", "CVE-2022-5678"}},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-id", "CVE-2021-1234,CVE-2022-5678", "-rl", "150", "-c", "25", "-target", target, "-jsonl"},
		},
		{
			name:   "rateLimit",
			cfg:    Config{RateLimit: intPtr(100)},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-rl", "100", "-c", "25", "-target", target, "-jsonl"},
		},
		{
			name:   "concurrency",
			cfg:    Config{Concurrency: intPtr(50)},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-rl", "150", "-c", "50", "-target", target, "-jsonl"},
		},
		{
			name:   "followRedirects true appends flag",
			cfg:    Config{FollowRedirects: boolPtr(true)},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-rl", "150", "-c", "25", "-follow-redirects", "-target", target, "-jsonl"},
		},
		{
			name:   "followRedirects false omits flag",
			cfg:    Config{FollowRedirects: boolPtr(false)},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-rl", "150", "-c", "25", "-target", target, "-jsonl"},
		},
		{
			name: "all fields populated with templateIds (id dominates)",
			cfg: Config{
				Severity:        []string{"high", "critical"},
				Tags:            []string{"cve"},
				ExcludeTags:     []string{"dos"},
				TemplateIds:     []string{"CVE-2021-1234"},
				RateLimit:       intPtr(200),
				Concurrency:     intPtr(40),
				FollowRedirects: boolPtr(true),
			},
			expect: []string{"-duc", "-silent", "-nc", "-t", defaultTemplateDir, "-id", "CVE-2021-1234", "-rl", "200", "-c", "40", "-follow-redirects", "-target", target, "-jsonl"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildCLIArgs(target, scanParams(tc.cfg, defaultTemplateDir))
			if len(got) != len(tc.expect) {
				t.Fatalf("arg count = %d, want %d\ngot:  %v\nwant: %v", len(got), len(tc.expect), got, tc.expect)
			}
			for i := range got {
				if got[i] != tc.expect[i] {
					t.Errorf("arg[%d] = %q, want %q\nfull: got %v, want %v", i, got[i], tc.expect[i], got, tc.expect)
				}
			}
		})
	}
}

func intPtr(v int) *int       { return &v }
func boolPtr(v bool) *bool    { return &v }
func strPtr(v string) *string { return &v }

// ---------------------------------------------------------------------------
// buildCLIArgs — id-mode priority, stable flags, manifest defaults
// ---------------------------------------------------------------------------

func TestBuildCLIArgs_IdPrioritized(t *testing.T) {
	target := "https://example.com"
	cfg := Config{
		Severity:    []string{"high", "critical"},
		Tags:        []string{"cve"},
		ExcludeTags: []string{"dos"},
		TemplateIds: []string{"CVE-2021-1234"},
	}
	got := buildCLIArgs(target, scanParams(cfg, defaultTemplateDir))
	for _, flag := range []string{"-severity", "-tags", "-etags"} {
		assertArgsNotContains(t, got, flag)
	}
	assertArgsContains(t, got, "-id")
	assertArgsContainsNext(t, got, "-id", "CVE-2021-1234")
	if got[len(got)-1] != "-jsonl" {
		t.Errorf("want -jsonl last, got %v", got)
	}
}

func TestBuildCLIArgs_HasDucSilentNc(t *testing.T) {
	target := "https://example.com"
	for name, cfg := range map[string]Config{
		"empty config": {},
		"id mode":      {TemplateIds: []string{"CVE-2021-1"}},
		"full config":  {Severity: []string{"high"}, Tags: []string{"cve"}, RateLimit: intPtr(10), Concurrency: intPtr(5)},
	} {
		t.Run(name, func(t *testing.T) {
			got := buildCLIArgs(target, scanParams(cfg, defaultTemplateDir))
			for _, flag := range []string{"-duc", "-silent", "-nc"} {
				assertArgsContains(t, got, flag)
			}
			targetIdx := indexOf(got, "-target")
			if targetIdx < 0 {
				t.Fatalf("missing -target in %v", got)
			}
			for _, flag := range []string{"-duc", "-silent", "-nc", "-t"} {
				if indexOf(got, flag) > targetIdx {
					t.Errorf("%q must come before -target, got %v", flag, got)
				}
			}
			if got[len(got)-1] != "-jsonl" {
				t.Errorf("want -jsonl last, got %v", got)
			}
		})
	}
}

func TestBuildCLIArgs_AppliesDefaults(t *testing.T) {
	target := "https://example.com"
	got := buildCLIArgs(target, scanParams(Config{}, defaultTemplateDir))
	assertArgsContainsNext(t, got, "-rl", "150")
	assertArgsContainsNext(t, got, "-c", "25")
}

func TestBuildCLIArgs_IncludesTemplateDir(t *testing.T) {
	if defaultTemplateDir != "/opt/nuclei-templates" {
		t.Fatalf("defaultTemplateDir = %q, want /opt/nuclei-templates", defaultTemplateDir)
	}
	target := "https://example.com"
	got := buildCLIArgs(target, scanParams(Config{}, defaultTemplateDir))
	assertArgsContainsNext(t, got, "-t", defaultTemplateDir)
	if idx := indexOf(got, "-t"); idx != 3 || idx+1 >= len(got) || got[idx-3] != "-duc" {
		t.Errorf("-t must be the 4th arg (right after -duc -silent -nc), got %v", got)
	}
}

func TestBuildCLIArgs_TemplateDirOverride(t *testing.T) {
	target := "https://example.com"
	got := buildCLIArgs(target, scanParams(Config{}, "/custom/templates"))
	assertArgsContainsNext(t, got, "-t", "/custom/templates")
	assertArgsNotContains(t, got, "/opt/nuclei-templates")
}

func indexOf(args []string, v string) int {
	for i, a := range args {
		if a == v {
			return i
		}
	}
	return -1
}

func assertArgsContains(t *testing.T, args []string, v string) {
	t.Helper()
	if indexOf(args, v) < 0 {
		t.Errorf("args %v missing %q", args, v)
	}
}

func assertArgsNotContains(t *testing.T, args []string, v string) {
	t.Helper()
	if indexOf(args, v) >= 0 {
		t.Errorf("args %v must not contain %q", args, v)
	}
}

// TestTemplateDir_AcceptsPluralEnv: worker injects NUCLEI_TEMPLATES_DIR (plural,
// docker.go) while the adapter historically read NUCLEI_TEMPLATE_DIR (singular).
// Both must work; singular wins when both are set.
func TestTemplateDir_AcceptsPluralEnv(t *testing.T) {
	t.Setenv("NUCLEI_TEMPLATE_DIR", "")
	t.Setenv("NUCLEI_TEMPLATES_DIR", "/plural/templates")
	if got := templateDir(); got != "/plural/templates" {
		t.Fatalf("templateDir() = %q, want /plural/templates", got)
	}

	t.Setenv("NUCLEI_TEMPLATE_DIR", "/singular/templates")
	t.Setenv("NUCLEI_TEMPLATES_DIR", "/plural/templates")
	if got := templateDir(); got != "/singular/templates" {
		t.Fatalf("templateDir() = %q, want /singular/templates (singular wins)", got)
	}
}

func assertArgsContainsNext(t *testing.T, args []string, flag, v string) {
	t.Helper()
	if !argsContainPair(args, flag, v) {
		t.Errorf("args %v missing pair %q %q", args, flag, v)
	}
}

func argsContainPair(args []string, flag, v string) bool {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag && args[i+1] == v {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// parseConfig — OASM_CONFIG JSON parsing tests
// ---------------------------------------------------------------------------

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr bool
		check   func(t *testing.T, cfg Config)
	}{
		{
			name:    "empty string yields zero config",
			raw:     "",
			wantErr: false,
			check: func(t *testing.T, cfg Config) {
				if len(cfg.Severity) != 0 || len(cfg.Tags) != 0 || cfg.RateLimit != nil || cfg.Concurrency != nil || cfg.FollowRedirects != nil {
					t.Errorf("expected zero Config, got %+v", cfg)
				}
			},
		},
		{
			name:    "malformed JSON yields zero config",
			raw:     `{not valid json`,
			wantErr: true,
		},
		{
			name: "valid JSON with all fields",
			raw:  `{"severity":["high","critical"],"tags":["cve"],"excludeTags":["dos"],"templateIds":["CVE-2021-1"],"rateLimit":100,"concurrency":30,"followRedirects":true}`,
			check: func(t *testing.T, cfg Config) {
				if len(cfg.Severity) != 2 || cfg.Severity[0] != "high" || cfg.Severity[1] != "critical" {
					t.Errorf("severity = %v", cfg.Severity)
				}
				if len(cfg.Tags) != 1 || cfg.Tags[0] != "cve" {
					t.Errorf("tags = %v", cfg.Tags)
				}
				if len(cfg.ExcludeTags) != 1 || cfg.ExcludeTags[0] != "dos" {
					t.Errorf("excludeTags = %v", cfg.ExcludeTags)
				}
				if len(cfg.TemplateIds) != 1 || cfg.TemplateIds[0] != "CVE-2021-1" {
					t.Errorf("templateIds = %v", cfg.TemplateIds)
				}
				if cfg.RateLimit == nil || *cfg.RateLimit != 100 {
					t.Errorf("rateLimit = %v", cfg.RateLimit)
				}
				if cfg.Concurrency == nil || *cfg.Concurrency != 30 {
					t.Errorf("concurrency = %v", cfg.Concurrency)
				}
				if cfg.FollowRedirects == nil || !*cfg.FollowRedirects {
					t.Errorf("followRedirects = %v", cfg.FollowRedirects)
				}
			},
		},
		{
			name: "valid JSON with only rateLimit",
			raw:  `{"rateLimit":50}`,
			check: func(t *testing.T, cfg Config) {
				if cfg.RateLimit == nil || *cfg.RateLimit != 50 {
					t.Errorf("rateLimit = %v", cfg.RateLimit)
				}
				if cfg.Concurrency != nil {
					t.Errorf("concurrency should be nil, got %v", *cfg.Concurrency)
				}
			},
		},
		{
			name: "empty JSON object yields zero config",
			raw:  `{}`,
			check: func(t *testing.T, cfg Config) {
				if len(cfg.Severity) != 0 || len(cfg.Tags) != 0 {
					t.Errorf("expected zero Config from {}, got %+v", cfg)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := parseConfig(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.check != nil {
				tc.check(t, cfg)
			}
		})
	}
}

// TestParseConfig_MalformedReturnsError: malformed OASM_CONFIG surfaces as an
// error so Execute fails loudly instead of silently scanning with defaults.
func TestParseConfig_MalformedReturnsError(t *testing.T) {
	cfg, err := parseConfig(`{not valid json`)
	if err == nil {
		t.Fatal("expected error for malformed JSON, got nil")
	}
	if len(cfg.Severity) != 0 || cfg.RateLimit != nil || cfg.Concurrency != nil {
		t.Errorf("config should be empty on error, got %+v", cfg)
	}
}

// ---------------------------------------------------------------------------
// Execute integration: OASM_CONFIG env → scanParams used
// ---------------------------------------------------------------------------

// setupTemplateDir creates a temp dir with one dummy file so the Execute
// preflight (templates dir must exist and be non-empty) passes in tests.
func setupTemplateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "dummy-template.yaml"), []byte("id: dummy\n"), 0o600); err != nil {
		t.Fatalf("write dummy template: %v", err)
	}
	return dir
}

func TestExecute_WithOASMConfig(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", `{"severity":["critical"],"rateLimit":200}`)
	dir := setupTemplateDir(t)
	t.Setenv("NUCLEI_TEMPLATE_DIR", dir)
	a := &NucleiAdapter{}
	ch := make(chan connector.Finding, 4)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// empty mode produces no findings — just verify it ran without error
	select {
	case b := <-ch:
		t.Fatalf("nothing should be emitted in empty mode, got: %+v", b)
	default:
	}
}

func TestExecute_EmptyOASMConfig(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", "")
	dir := setupTemplateDir(t)
	t.Setenv("NUCLEI_TEMPLATE_DIR", dir)
	a := &NucleiAdapter{}
	ch := make(chan connector.Finding, 4)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
}

func TestExecute_MalformedOASMConfig(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", "not-json!!!")
	dir := setupTemplateDir(t)
	t.Setenv("NUCLEI_TEMPLATE_DIR", dir)
	a := &NucleiAdapter{}
	ch := make(chan connector.Finding, 4)
	err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch)
	if err == nil {
		t.Fatal("expected error for malformed OASM_CONFIG")
	}
	if got := err.Error(); !strings.Contains(got, "invalid OASM_CONFIG") {
		t.Fatalf("error should mention invalid OASM_CONFIG, got: %v", got)
	}
}

// TestExecute_MissingTemplateDirFailsFast: a missing/empty template dir must
// fail with a clear adapter error, not nuclei's cryptic FTL on stdout.
func TestExecute_MissingTemplateDirFailsFast(t *testing.T) {
	t.Setenv("NUCLEI_TEMPLATE_DIR", "/nonexistent-templates-xyz")
	t.Setenv("NUCLEI_TEMPLATES_DIR", "")
	fakeBin := filepath.Join(t.TempDir(), "nuclei-should-not-exist")
	t.Setenv("NUCLEI_BIN", fakeBin) // would fail if reached; preflight must catch first
	t.Setenv("OASM_CONFIG", "")

	a := &NucleiAdapter{}
	out := make(chan connector.Finding, 1)
	err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, out)
	close(out)
	if err == nil {
		t.Fatal("want error for missing template dir, got nil")
	}
	if got := err.Error(); !strings.Contains(got, "/nonexistent-templates-xyz") {
		t.Fatalf("error must name the bad dir, got: %v", err)
	}
}
