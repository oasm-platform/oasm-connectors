package main

import (
	"slices"
	"testing"
)

func TestLoadArjunConfig_UnsetIsZeroConfig(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadArjunConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Wordlist != "" || cfg.Method != "" || cfg.Threads != 0 || cfg.ChunkSize != 0 ||
		cfg.Timeout != 0 || cfg.Delay != 0 || cfg.Stable || cfg.RateLimit != 0 ||
		cfg.DisableRedirects || len(cfg.Headers) != 0 || cfg.Include != "" || cfg.MaxUrls != 0 {
		t.Fatalf("expected zero config, got %+v", cfg)
	}
}

func TestLoadArjunConfig_ParsesCamelCaseKeys(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"wordlist":"large","method":"POST","threads":10,"chunkSize":500,"timeout":20,"delay":1.5,"stable":true,"rateLimit":100,"disableRedirects":true,"headers":["X-A: 1","X-B: 2"],"include":"status,body","maxUrls":50}`)
	cfg, err := loadArjunConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Wordlist != "large" || cfg.Method != "POST" || cfg.Threads != 10 || cfg.ChunkSize != 500 ||
		cfg.Timeout != 20 || cfg.Delay != 1.5 || !cfg.Stable || cfg.RateLimit != 100 ||
		!cfg.DisableRedirects || !slices.Equal(cfg.Headers, []string{"X-A: 1", "X-B: 2"}) ||
		cfg.Include != "status,body" || cfg.MaxUrls != 50 {
		t.Fatalf("config not parsed: %+v", cfg)
	}
}

func TestLoadArjunConfig_InvalidJSONErrors(t *testing.T) {
	t.Setenv("OASM_CONFIG", "{not json")
	if _, err := loadArjunConfig(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// C8 args: full + default buildArjunArgs vectors, deterministically ordered.
func TestBuildArjunArgs_FullAndDefaults(t *testing.T) {
	full := &arjunConfig{
		Wordlist:         "large",
		Method:           "POST",
		Threads:          10,
		ChunkSize:        500,
		Timeout:          20,
		Delay:            1.5,
		Stable:           true,
		RateLimit:        100,
		DisableRedirects: true,
		Headers:          []string{"X-A: 1", "X-B: 2"},
		Include:          "status,body",
		MaxUrls:          50,
	}
	wantFull := []string{
		"-u", "https://example.com", "-oJ", "/tmp/out.json",
		"-w", "large", "-m", "POST", "-t", "10", "-c", "500", "-T", "20",
		"-d", "1.5", "--stable", "--rate-limit", "100",
		"--headers", "X-A: 1\nX-B: 2", "--include", "status,body", "--disable-redirects",
	}
	if got := buildArjunArgs("https://example.com", "/tmp/out.json", full); !slices.Equal(got, wantFull) {
		t.Errorf("full cfg argv:\n got %v\nwant %v", got, wantFull)
	}

	// Zero config still emits wordlist/method/threads/chunk/timeout/rate-limit
	// with defaults; headers/delay/include/redirects omitted.
	wantZero := []string{
		"-u", "https://example.com", "-oJ", "/tmp/out.json",
		"-w", "medium", "-m", "GET", "-t", "5", "-c", "250", "-T", "15",
		"--rate-limit", "9999",
	}
	if got := buildArjunArgs("https://example.com", "/tmp/out.json", &arjunConfig{}); !slices.Equal(got, wantZero) {
		t.Errorf("zero cfg argv:\n got %v\nwant %v", got, wantZero)
	}
}

// --headers must never be emitted with an empty list: a bare --headers would
// launch Arjun's interactive nano editor and hang the run.
func TestBuildArjunArgs_OmitsBareHeaders(t *testing.T) {
	got := buildArjunArgs("https://example.com", "/tmp/out.json", &arjunConfig{Headers: []string{}})
	if slices.Contains(got, "--headers") {
		t.Fatalf("--headers must be absent when list is empty: %v", got)
	}
}
