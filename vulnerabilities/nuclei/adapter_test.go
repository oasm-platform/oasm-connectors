package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
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
		fakeBinPath = filepath.Join(dir, "fake-nuclei.exe")
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
	ch := make(chan []byte, 4)
	err := a.Execute(context.Background(), map[string]any{}, ch)
	if err == nil {
		t.Fatal("expected error for missing target")
	}
	if got := err.Error(); !strings.Contains(got, "target required") {
		t.Fatalf("want 'target required', got: %v", got)
	}
	select {
	case b := <-ch:
		t.Fatalf("nothing should be emitted, got: %s", b)
	default:
	}
}

// TestNucleiExecute_StreamsJsonlFindings is the happy path: JSONL findings are
// streamed through, banner/noise lines are skipped.
func TestNucleiExecute_StreamsJsonlFindings(t *testing.T) {
	t.Setenv("NUCLEI_BIN", ensureFakeNuclei(t))
	a := &NucleiAdapter{}
	ch := make(chan []byte, 8)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	close(ch)
	var findings []map[string]any
	for b := range ch {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("emitted line is not valid JSON object: %v (%s)", err, b)
		}
		findings = append(findings, m)
	}
	if len(findings) != 2 {
		t.Fatalf("expected exactly 2 findings (noise skipped), got %d", len(findings))
	}
	wantIDs := []string{"cve-2023-1234", "cve-2024-5678"}
	for i, id := range wantIDs {
		if findings[i]["template-id"] != id {
			t.Errorf("finding[%d] template-id = %v, want %v", i, findings[i]["template-id"], id)
		}
	}
	if findings[0]["matched-at"] != "https://example.com" {
		t.Errorf("matched-at mismatch: %v", findings[0]["matched-at"])
	}
}

// TestNucleiExecute_EmptyOutputNoError: exit 0 with no output -> no error, no emission.
func TestNucleiExecute_EmptyOutputNoError(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	a := &NucleiAdapter{}
	ch := make(chan []byte, 4)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("expected nil error for empty output, got: %v", err)
	}
	select {
	case b := <-ch:
		t.Fatalf("nothing should be emitted, got: %s", b)
	default:
	}
}

// TestNucleiExecute_ReturnsErrorOnNonZeroExit: non-zero exit surfaces stderr.
func TestNucleiExecute_ReturnsErrorOnNonZeroExit(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "fail")
	a := &NucleiAdapter{}
	ch := make(chan []byte, 4)
	err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch)
	if err == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if got := err.Error(); !strings.Contains(got, "connection refused") {
		t.Fatalf("error should contain stderr fragment, got: %v", got)
	}
}

// ---------------------------------------------------------------------------
// buildArgs — table-driven tests for config → CLI flag mapping
// ---------------------------------------------------------------------------

func TestBuildArgs(t *testing.T) {
	target := "https://example.com"

	tests := []struct {
		name   string
		cfg    Config
		expect []string
	}{
		{
			name:   "empty config yields only target and jsonl",
			cfg:    Config{},
			expect: []string{"-target", target, "-jsonl"},
		},
		{
			name:   "severity single",
			cfg:    Config{Severity: []string{"high"}},
			expect: []string{"-severity", "high", "-target", target, "-jsonl"},
		},
		{
			name:   "severity multiple csv",
			cfg:    Config{Severity: []string{"high", "critical"}},
			expect: []string{"-severity", "high,critical", "-target", target, "-jsonl"},
		},
		{
			name:   "tags csv",
			cfg:    Config{Tags: []string{"cve", "xss"}},
			expect: []string{"-tags", "cve,xss", "-target", target, "-jsonl"},
		},
		{
			name:   "excludeTags csv",
			cfg:    Config{ExcludeTags: []string{"dos"}},
			expect: []string{"-etags", "dos", "-target", target, "-jsonl"},
		},
		{
			name:   "templateIds csv",
			cfg:    Config{TemplateIds: []string{"CVE-2021-1234", "CVE-2022-5678"}},
			expect: []string{"-id", "CVE-2021-1234,CVE-2022-5678", "-target", target, "-jsonl"},
		},
		{
			name:   "rateLimit",
			cfg:    Config{RateLimit: intPtr(100)},
			expect: []string{"-rl", "100", "-target", target, "-jsonl"},
		},
		{
			name:   "concurrency",
			cfg:    Config{Concurrency: intPtr(50)},
			expect: []string{"-c", "50", "-target", target, "-jsonl"},
		},
		{
			name:   "followRedirects true appends flag",
			cfg:    Config{FollowRedirects: boolPtr(true)},
			expect: []string{"-follow-redirects", "-target", target, "-jsonl"},
		},
		{
			name:   "followRedirects false omits flag",
			cfg:    Config{FollowRedirects: boolPtr(false)},
			expect: []string{"-target", target, "-jsonl"},
		},
		{
			name: "all fields populated",
			cfg: Config{
				Severity:        []string{"high", "critical"},
				Tags:            []string{"cve"},
				ExcludeTags:     []string{"dos"},
				TemplateIds:     []string{"CVE-2021-1234"},
				RateLimit:       intPtr(200),
				Concurrency:     intPtr(40),
				FollowRedirects: boolPtr(true),
			},
			expect: []string{"-severity", "high,critical", "-tags", "cve", "-etags", "dos", "-id", "CVE-2021-1234", "-rl", "200", "-c", "40", "-follow-redirects", "-target", target, "-jsonl"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildArgs(target, tc.cfg)
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

// ---------------------------------------------------------------------------
// Execute integration: OASM_CONFIG env → buildArgs used
// ---------------------------------------------------------------------------

func TestExecute_WithOASMConfig(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", `{"severity":["critical"],"rateLimit":200}`)
	a := &NucleiAdapter{}
	ch := make(chan []byte, 4)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	// empty mode produces no findings — just verify it ran without error
	select {
	case b := <-ch:
		t.Fatalf("nothing should be emitted in empty mode, got: %s", b)
	default:
	}
}

func TestExecute_EmptyOASMConfig(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", "")
	a := &NucleiAdapter{}
	ch := make(chan []byte, 4)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
}

func TestExecute_MalformedOASMConfig(t *testing.T) {
	bin := ensureFakeNuclei(t)
	t.Setenv("NUCLEI_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", "not-json!!!")
	a := &NucleiAdapter{}
	ch := make(chan []byte, 4)
	if err := a.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
}
