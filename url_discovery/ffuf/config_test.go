package main

import (
	"slices"
	"testing"
)

func TestLoadFfufConfig_UnsetIsZeroConfig(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadFfufConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Threads != 0 || cfg.Timeout != 0 || cfg.Wordlist != "" ||
		cfg.Recursion || cfg.FollowRedirects || cfg.AutoCalibration ||
		len(cfg.Extensions) != 0 || len(cfg.Headers) != 0 {
		t.Fatalf("expected zero config, got %+v", cfg)
	}
}

func TestLoadFfufConfig_ParsesCamelCaseKeys(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"wordlist":"big","extensions":["php"],"matchCodes":"200","filterCodes":"404","filterSize":"0","recursion":true,"recursionDepth":2,"threads":50,"rate":100,"delay":"0.1","timeout":15,"followRedirects":true,"autoCalibration":true,"headers":["X-A: b"],"proxy":"http://p","method":"POST","data":"a=b","maxTime":300,"maxUrls":5000}`)
	cfg, err := loadFfufConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Wordlist != "big" || !slices.Equal(cfg.Extensions, []string{"php"}) ||
		cfg.MatchCodes != "200" || cfg.FilterCodes != "404" || cfg.FilterSize != "0" ||
		!cfg.Recursion || cfg.RecursionDepth != 2 || cfg.Threads != 50 || cfg.Rate != 100 ||
		cfg.Delay != "0.1" || cfg.Timeout != 15 || !cfg.FollowRedirects || !cfg.AutoCalibration ||
		!slices.Equal(cfg.Headers, []string{"X-A: b"}) || cfg.Proxy != "http://p" ||
		cfg.Method != "POST" || cfg.Data != "a=b" || cfg.MaxTime != 300 || cfg.MaxUrls != 5000 {
		t.Fatalf("config not parsed: %+v", cfg)
	}
}

func TestLoadFfufConfig_InvalidJSONErrors(t *testing.T) {
	t.Setenv("OASM_CONFIG", "{not json")
	if _, err := loadFfufConfig(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

// Full config vector, deterministically ordered; zero config keeps -t/-timeout
// with defaults.
func TestBuildFfufArgs_FullAndDefaults(t *testing.T) {
	full := &ffufConfig{
		Extensions:      []string{"php", "html"},
		MatchCodes:      "200,204,301",
		FilterCodes:     "404",
		FilterSize:      "0",
		Recursion:       true,
		RecursionDepth:  2,
		Threads:         50,
		Rate:            100,
		Delay:           "0.1",
		Timeout:         15,
		FollowRedirects: true,
		AutoCalibration: true,
		Headers:         []string{"X-Api-Key: secret", "Authorization: Bearer t"},
		Proxy:           "http://127.0.0.1:8080",
		Method:          "POST",
		Data:            "a=b",
		MaxTime:         300,
		MaxUrls:         5000,
	}
	wantFull := []string{
		"-json", "-s", "-noninteractive",
		"-u", "https://example.com/FUZZ",
		"-w", "/opt/wordlists/ffuf/common.txt",
		"-X", "POST",
		"-d", "a=b",
		"-e", "php,html",
		"-mc", "200,204,301",
		"-fc", "404",
		"-fs", "0",
		"-t", "50",
		"-timeout", "15",
		"-rate", "100",
		"-p", "0.1",
		"-r", "-ac",
		"-recursion", "-recursion-depth", "2",
		"-maxtime", "300",
		"-H", "X-Api-Key: secret",
		"-H", "Authorization: Bearer t",
		"-x", "http://127.0.0.1:8080",
	}
	if got := buildFfufArgs("https://example.com", "/opt/wordlists/ffuf/common.txt", full); !slices.Equal(got, wantFull) {
		t.Errorf("full cfg argv:\n got %v\nwant %v", got, wantFull)
	}

	// Zero config still emits -t/-timeout with defaults.
	wantZero := []string{
		"-json", "-s", "-noninteractive",
		"-u", "https://example.com/FUZZ",
		"-w", "/wl/common.txt",
		"-t", "40", "-timeout", "10",
	}
	if got := buildFfufArgs("https://example.com", "/wl/common.txt", &ffufConfig{}); !slices.Equal(got, wantZero) {
		t.Errorf("zero cfg argv:\n got %v\nwant %v", got, wantZero)
	}
}

func TestResolveFfufWordlist_EnumToPath(t *testing.T) {
	t.Setenv("FFUF_WORDLIST_DIR", "/custom/wl")
	cases := map[string]string{
		"common":                  "/custom/wl/common.txt",
		"raft-small-directories":  "/custom/wl/raft-small-directories.txt",
		"raft-medium-directories": "/custom/wl/raft-medium-directories.txt",
		"big":                     "/custom/wl/big.txt",
		"dirbuster-small":         "/custom/wl/DirBuster-2007_directory-list-2.3-small.txt",
		"dirbuster-medium":        "/custom/wl/DirBuster-2007_directory-list-2.3-medium.txt",
		"":                        "/custom/wl/common.txt", // empty -> common
		"bogus":                   "/custom/wl/common.txt", // unknown -> common
	}
	for enum, want := range cases {
		if got := resolveFfufWordlist(&ffufConfig{Wordlist: enum}); got != want {
			t.Errorf("wordlist %q: got %q want %q", enum, got, want)
		}
	}

	// Unset/blank dir falls back to the image default.
	t.Setenv("FFUF_WORDLIST_DIR", "")
	if got := resolveFfufWordlist(&ffufConfig{Wordlist: "big"}); got != "/opt/wordlists/ffuf/big.txt" {
		t.Errorf("default dir: got %q", got)
	}
}
