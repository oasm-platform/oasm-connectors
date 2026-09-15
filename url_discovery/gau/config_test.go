package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

func TestLoadGauConfig_UnsetIsZeroConfig(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadGauConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Threads != 0 || cfg.Timeout != 0 || cfg.Retries != 0 || len(cfg.Providers) != 0 {
		t.Fatalf("expected zero config, got %+v", cfg)
	}
}

func TestLoadGauConfig_ParsesCamelCaseKeys(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"providers":["wayback"],"subs":true,"threads":3,"timeout":10,"retries":2,"proxy":"http://p","from":"201901","to":"202601"}`)
	cfg, err := loadGauConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(cfg.Providers, []string{"wayback"}) || !cfg.Subs || cfg.Threads != 3 ||
		cfg.Timeout != 10 || cfg.Retries != 2 || cfg.Proxy != "http://p" ||
		cfg.From != "201901" || cfg.To != "202601" {
		t.Fatalf("config not parsed: %+v", cfg)
	}
}

func TestLoadGauConfig_InvalidJSONErrors(t *testing.T) {
	t.Setenv("OASM_CONFIG", "{not json")
	if _, err := loadGauConfig(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// C7 args: full config vector, deterministically ordered.
func TestBuildGauArgs_FullAndDefaults(t *testing.T) {
	full := &gauConfig{
		Providers: []string{"wayback", "otx"},
		Subs:      true,
		Threads:   5,
		Timeout:   45,
		Retries:   1,
		Proxy:     "http://127.0.0.1:8080",
		From:      "201901",
		To:        "202601",
	}
	wantFull := []string{
		"--threads", "5", "--timeout", "45", "--retries", "1",
		"--providers", "wayback,otx", "--subs",
		"--proxy", "http://127.0.0.1:8080",
		"--from", "201901", "--to", "202601",
		"example.com",
	}
	if got := buildGauArgs("example.com", full); !slices.Equal(got, wantFull) {
		t.Errorf("full cfg argv:\n got %v\nwant %v", got, wantFull)
	}

	// Zero config still emits threads/timeout/retries with defaults.
	wantZero := []string{"--threads", "5", "--timeout", "45", "--retries", "5", "example.com"}
	if got := buildGauArgs("example.com", &gauConfig{}); !slices.Equal(got, wantZero) {
		t.Errorf("zero cfg argv:\n got %v\nwant %v", got, wantZero)
	}
}

// C7 args: the argv actually handed to the gau binary (captured by the fake)
// matches buildGauArgs, proving Execute wires config -> CLI correctly.
func TestGauExecute_PassesBuiltArgsToBinary(t *testing.T) {
	bin := ensureFakeGau(t)
	argsFile := filepath.Join(t.TempDir(), "args.json")

	t.Setenv("GAU_BIN", bin)
	t.Setenv("FAKE_MODE", "default")
	t.Setenv("FAKE_ARGS_FILE", argsFile)
	t.Setenv("OASM_CONFIG", `{"providers":["wayback","otx"],"subs":true,"threads":5,"timeout":45,"retries":1,"proxy":"http://127.0.0.1:8080","from":"201901","to":"202601"}`)

	out := make(chan connector.Finding, 64)
	err := GauAdapter{}.Execute(context.Background(), map[string]any{"target": "https://example.com/x"}, out)
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
	want := []string{
		"--threads", "5", "--timeout", "45", "--retries", "1",
		"--providers", "wayback,otx", "--subs",
		"--proxy", "http://127.0.0.1:8080",
		"--from", "201901", "--to", "202601",
		"example.com",
	}
	if !slices.Equal(got, want) {
		t.Errorf("captured argv:\n got %v\nwant %v", got, want)
	}
}
