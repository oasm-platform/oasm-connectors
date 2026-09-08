package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

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

func intPtr(v int) *int    { return &v }
func boolPtr(v bool) *bool { return &v }

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

func TestExecute_MalformedOASMConfig(t *testing.T) {
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

func TestEmitFinding_RecoversCallbackPanic(t *testing.T) {
	t.Run("panicking mapFn", func(t *testing.T) {
		ch := make(chan connector.Finding, 1)
		sent, err := emitFinding(context.Background(), nil, ch, func(_ *nucleiOutput.ResultEvent) (connector.Finding, error) {
			panic("injected")
		})
		if sent {
			t.Error("expected sent=false")
		}
		if err == nil || !strings.Contains(err.Error(), "nuclei event handler panic: injected") {
			t.Fatalf("expected panic recovery error, got: %v", err)
		}
	})

	t.Run("valid mapFn and event", func(t *testing.T) {
		ch := make(chan connector.Finding, 1)
		ev := &nucleiOutput.ResultEvent{
			Info: model.Info{
				Name:           "test-finding",
				SeverityHolder: severity.Holder{Severity: severity.Info},
			},
		}
		sent, err := emitFinding(context.Background(), ev, ch, resultEventToFinding)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !sent {
			t.Error("expected sent=true")
		}
		f := <-ch
		if f.Name != "test-finding" {
			t.Errorf("Name = %q, want test-finding", f.Name)
		}
	})

	t.Run("context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		ch := make(chan connector.Finding) // unbuffered — send blocks, cancel wins
		ev := &nucleiOutput.ResultEvent{
			Info: model.Info{
				Name:           "test-finding",
				SeverityHolder: severity.Holder{Severity: severity.Info},
			},
		}
		sent, err := emitFinding(ctx, ev, ch, resultEventToFinding)
		if sent {
			t.Error("expected sent=false")
		}
		if err != context.Canceled {
			t.Fatalf("expected context.Canceled, got: %v", err)
		}
	})
}
