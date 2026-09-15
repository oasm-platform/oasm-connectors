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

func TestLoadKatanaConfig_UnsetIsZeroConfig(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadKatanaConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Depth != 0 || cfg.JsCrawl != nil || cfg.CrawlDuration != 0 || cfg.Timeout != 0 ||
		cfg.Concurrency != 0 || cfg.Parallelism != 0 || cfg.RateLimit != 0 || cfg.Retries != 0 ||
		cfg.Proxy != "" || len(cfg.Headers) != 0 || cfg.FilterSimilar || cfg.FilterSimilarThreshold != 0 ||
		cfg.MaxDomainPages != 0 || len(cfg.ExtensionMatch) != 0 || len(cfg.ExtensionFilter) != 0 ||
		cfg.CrawlScope != "" || cfg.MaxUrls != 0 {
		t.Fatalf("expected zero config, got %+v", cfg)
	}
}

func TestLoadKatanaConfig_ParsesCamelCaseKeys(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"depth":5,"jsCrawl":false,"crawlDuration":120,"timeout":7,"concurrency":20,`+
		`"parallelism":4,"rateLimit":75,"retries":2,"proxy":"http://p","headers":["X-Api-Key: k1"],`+
		`"filterSimilar":true,"filterSimilarThreshold":20,"maxDomainPages":50,`+
		`"extensionMatch":["php","html"],"extensionFilter":["png","css"],"crawlScope":".*\\.example\\.com","maxUrls":100}`)
	cfg, err := loadKatanaConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.JsCrawl == nil || *cfg.JsCrawl != false {
		t.Fatalf("jsCrawl should be parsed as explicit false, got %v", cfg.JsCrawl)
	}
	if cfg.Depth != 5 || cfg.CrawlDuration != 120 || cfg.Timeout != 7 || cfg.Concurrency != 20 ||
		cfg.Parallelism != 4 || cfg.RateLimit != 75 || cfg.Retries != 2 || cfg.Proxy != "http://p" ||
		!slices.Equal(cfg.Headers, []string{"X-Api-Key: k1"}) || !cfg.FilterSimilar ||
		cfg.FilterSimilarThreshold != 20 || cfg.MaxDomainPages != 50 ||
		!slices.Equal(cfg.ExtensionMatch, []string{"php", "html"}) ||
		!slices.Equal(cfg.ExtensionFilter, []string{"png", "css"}) ||
		cfg.CrawlScope != `.*\.example\.com` || cfg.MaxUrls != 100 {
		t.Fatalf("config not parsed: %+v", cfg)
	}

	// An omitted jsCrawl must stay nil so the adapter defaults it to true.
	t.Setenv("OASM_CONFIG", `{"depth":3}`)
	omitted, err := loadKatanaConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if omitted.JsCrawl != nil {
		t.Fatalf("omitted jsCrawl must stay nil, got %v", *omitted.JsCrawl)
	}
}

func TestLoadKatanaConfig_InvalidJSONErrors(t *testing.T) {
	t.Setenv("OASM_CONFIG", "{not json")
	if _, err := loadKatanaConfig(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func boolPtr(b bool) *bool { return &b }

// C7 args: deterministic argv vectors (full config + zero config). The full
// vector pins: -duc first (no update-check egress), always-emitted core flags,
// and CSV-quoting of a header value containing a comma (pflag string[] splits
// raw args on commas via encoding/csv).
func TestBuildKatanaArgs_FullAndDefaults(t *testing.T) {
	full := &katanaConfig{
		Depth: 5, JsCrawl: boolPtr(false), CrawlDuration: 120, Timeout: 7, Concurrency: 20,
		Parallelism: 4, RateLimit: 75, Retries: 2, Proxy: "http://127.0.0.1:8080",
		Headers:       []string{"X-Api-Key: k1", "Accept: text/html,application/json"},
		FilterSimilar: true, FilterSimilarThreshold: 20, MaxDomainPages: 50,
		ExtensionFilter: []string{"png", "css"}, ExtensionMatch: []string{"php", "html"},
		CrawlScope: `.*\.example\.com`, MaxUrls: 100,
	}
	wantFull := []string{
		"-duc", "-silent", "-nc",
		"-d", "5",
		"-ct", "120",
		"-timeout", "7",
		"-c", "20",
		"-p", "4",
		"-rl", "75",
		"-retry", "2",
		// jsCrawl=false -> no -jc
		"-fsu", "-fst", "20",
		"-mdp", "50",
		"-cs", `.*\.example\.com`,
		"-em", "php,html",
		"-ef", "png,css",
		"-proxy", "http://127.0.0.1:8080",
		"-H", "X-Api-Key: k1",
		"-H", `"Accept: text/html,application/json"`,
		"-u", "example.com",
	}
	if got := buildKatanaArgs("example.com", full); !slices.Equal(got, wantFull) {
		t.Errorf("full cfg argv:\n got %v\nwant %v", got, wantFull)
	}

	// Zero config proves defaults and the nil-pointer jsCrawl=true.
	wantZero := []string{
		"-duc", "-silent", "-nc",
		"-d", "3",
		"-ct", "0",
		"-timeout", "10",
		"-c", "10",
		"-p", "10",
		"-rl", "150",
		"-retry", "1",
		"-jc",
		"-u", "example.com",
	}
	if got := buildKatanaArgs("example.com", &katanaConfig{}); !slices.Equal(got, wantZero) {
		t.Errorf("zero cfg argv:\n got %v\nwant %v", got, wantZero)
	}
}

// S12 args: the argv actually handed to the katana binary (captured by the
// fake) matches buildKatanaArgs, proving Execute wires OASM_CONFIG -> CLI.
//
// NOTE: this test needs ensureFakeKatana (adapter_test.go) and KatanaAdapter
// (adapter.go), so it only compiles from Wave 3 on.
func TestKatanaExecute_PassesBuiltArgsToBinary(t *testing.T) {
	bin := ensureFakeKatana(t)
	argsFile := filepath.Join(t.TempDir(), "args.json")

	t.Setenv("KATANA_BIN", bin)
	t.Setenv("FAKE_MODE", "default")
	t.Setenv("FAKE_ARGS_FILE", argsFile)
	t.Setenv("OASM_CONFIG", `{"depth":4,"jsCrawl":false,"crawlDuration":60,"timeout":9,"concurrency":7,`+
		`"parallelism":3,"rateLimit":50,"retries":2,"proxy":"http://p:8080","headers":["X-Test: 1"],`+
		`"filterSimilar":true,"filterSimilarThreshold":15,"maxDomainPages":25,`+
		`"extensionMatch":["php"],"extensionFilter":["css"],"crawlScope":"scope-regex","maxUrls":100}`)

	out := make(chan connector.Finding, 64)
	err := KatanaAdapter{}.Execute(context.Background(), map[string]any{"target": "https://example.com/x"}, out)
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
		"-duc", "-silent", "-nc", "-d", "4", "-ct", "60", "-timeout", "9", "-c", "7", "-p", "3",
		"-rl", "50", "-retry", "2", "-fsu", "-fst", "15", "-mdp", "25", "-cs", "scope-regex",
		"-em", "php", "-ef", "css", "-proxy", "http://p:8080", "-H", "X-Test: 1", "-u", "example.com",
	}
	if !slices.Equal(got, want) {
		t.Errorf("captured argv:\n got %v\nwant %v", got, want)
	}
}
