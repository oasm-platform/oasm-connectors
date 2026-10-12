package main

import (
	"slices"
	"testing"
)

func TestLoadDirsearchConfig_UnsetIsZeroConfig(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadDirsearchConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Wordlist != "" || cfg.Threads != 0 || cfg.Timeout != 0 || cfg.MaxTime != 0 ||
		cfg.MaxUrls != 0 || cfg.Recursive || len(cfg.Extensions) != 0 {
		t.Fatalf("expected zero config, got %+v", cfg)
	}
}

func TestLoadDirsearchConfig_ParsesCamelCaseKeys(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"wordlist":"common","extensions":["php","html"],"threads":10,"recursive":true,"maxRecursionDepth":3,"includeStatus":"200,301","excludeStatus":"404","excludeExtensions":["js","css"],"method":"GET","headers":["X-A: 1"],"proxy":"http://p","timeout":30,"randomUserAgent":true,"maxTime":300,"maxUrls":500}`)
	cfg, err := loadDirsearchConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Wordlist != "common" || !slices.Equal(cfg.Extensions, []string{"php", "html"}) ||
		cfg.Threads != 10 || !cfg.Recursive || cfg.MaxRecursionDepth != 3 ||
		cfg.IncludeStatus != "200,301" || cfg.ExcludeStatus != "404" ||
		!slices.Equal(cfg.ExcludeExtensions, []string{"js", "css"}) || cfg.Method != "GET" ||
		!slices.Equal(cfg.Headers, []string{"X-A: 1"}) || cfg.Proxy != "http://p" ||
		cfg.Timeout != 30 || !cfg.RandomUserAgent || cfg.MaxTime != 300 || cfg.MaxUrls != 500 {
		t.Fatalf("config not parsed: %+v", cfg)
	}
}

func TestLoadDirsearchConfig_InvalidJSONErrors(t *testing.T) {
	t.Setenv("OASM_CONFIG", "{not json")
	if _, err := loadDirsearchConfig(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestResolveDirsearchWordlist_EnumToPathAndEnvOverride(t *testing.T) {
	t.Setenv("DIRSEARCH_WORDLIST_DIR", "")
	if got := resolveDirsearchWordlist(&dirsearchConfig{}); got != "/opt/wordlists/dirsearch/dicc.txt" {
		t.Errorf("empty wordlist: got %q", got)
	}
	if got := resolveDirsearchWordlist(&dirsearchConfig{Wordlist: "default"}); got != "/opt/wordlists/dirsearch/dicc.txt" {
		t.Errorf("default wordlist: got %q", got)
	}
	if got := resolveDirsearchWordlist(&dirsearchConfig{Wordlist: "common"}); got != "/opt/wordlists/dirsearch/common.txt" {
		t.Errorf("common wordlist: got %q", got)
	}

	t.Setenv("DIRSEARCH_WORDLIST_DIR", "/custom/wl")
	if got := resolveDirsearchWordlist(&dirsearchConfig{Wordlist: "vcs"}); got != "/custom/wl/vcs.txt" {
		t.Errorf("env override: got %q", got)
	}
}

func TestBuildDirsearchArgs_FullAndDefaults(t *testing.T) {
	full := &dirsearchConfig{
		Wordlist:          "common",
		Extensions:        []string{"php", "html"},
		Threads:           10,
		Recursive:         true,
		MaxRecursionDepth: 3,
		IncludeStatus:     "200,301",
		ExcludeStatus:     "404",
		ExcludeExtensions: []string{"js", "css"},
		Method:            "GET",
		Headers:           []string{"X-A: 1", "X-B: 2"},
		Proxy:             "http://127.0.0.1:8080",
		Timeout:           30,
		RandomUserAgent:   true,
		MaxTime:           300,
		MaxUrls:           500,
	}
	wantFull := []string{
		"-u", "https://example.com",
		"-O", "json",
		"-o", "/tmp/out.json",
		"-q",
		"--no-color",
		"-w", "/opt/wordlists/dirsearch/common.txt",
		"-e", "php,html",
		"-t", "10",
		"-r",
		"-R", "3",
		"-i", "200,301",
		"-x", "404",
		"--exclude-extensions", "js,css",
		"-m", "GET",
		"-H", "X-A: 1",
		"-H", "X-B: 2",
		"-p", "http://127.0.0.1:8080",
		"--timeout", "30",
		"--random-agent",
		"--max-time", "300",
	}
	if got := buildDirsearchArgs("https://example.com", "/opt/wordlists/dirsearch/common.txt", "/tmp/out.json", full); !slices.Equal(got, wantFull) {
		t.Errorf("full cfg argv:\n got %v\nwant %v", got, wantFull)
	}

	// Zero config still emits the fixed head plus -w and -t with defaults.
	wantZero := []string{
		"-u", "https://example.com",
		"-O", "json",
		"-o", "/tmp/out.json",
		"-q",
		"--no-color",
		"-w", "/opt/wordlists/dirsearch/dicc.txt",
		"-t", "25",
	}
	if got := buildDirsearchArgs("https://example.com", "/opt/wordlists/dirsearch/dicc.txt", "/tmp/out.json", &dirsearchConfig{}); !slices.Equal(got, wantZero) {
		t.Errorf("zero cfg argv:\n got %v\nwant %v", got, wantZero)
	}

	// Recursive with depth 0 emits -r but no -R.
	wantRec := []string{
		"-u", "https://example.com",
		"-O", "json",
		"-o", "/tmp/out.json",
		"-q",
		"--no-color",
		"-w", "/opt/wordlists/dirsearch/dicc.txt",
		"-t", "25",
		"-r",
	}
	if got := buildDirsearchArgs("https://example.com", "/opt/wordlists/dirsearch/dicc.txt", "/tmp/out.json", &dirsearchConfig{Recursive: true}); !slices.Equal(got, wantRec) {
		t.Errorf("recursive depth-0 argv:\n got %v\nwant %v", got, wantRec)
	}
}
