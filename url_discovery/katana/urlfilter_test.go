package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

func TestLoadKatanaConfig_ParsesUrlPatterns(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"matchRegex":["/login","/admin"],"filterRegex":["\\.css$"]}`)
	cfg, err := connector.LoadConfig[katanaConfig](t.Context())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.Equal(cfg.MatchRegex, []string{"/login", "/admin"}) ||
		!slices.Equal(cfg.FilterRegex, []string{`\.css$`}) {
		t.Fatalf("patterns not parsed: %+v", cfg)
	}
}

// goflags normalizes every -mr/-fr entry: it trims spaces and cuts at the
// first '#' as a comment. Only lists katana would evaluate verbatim are pushed
// down.
func TestKatanaCanEvaluate(t *testing.T) {
	cases := []struct {
		name     string
		patterns []string
		want     bool
	}{
		{"no patterns", nil, false},
		{"plain patterns", []string{`/login`, `\.php(\?|$)`}, true},
		{"comma is kept verbatim", []string{`/v[0-9]{1,3}/`}, true},
		{"hash would be cut as a comment", []string{`/login`, `#/admin`}, false},
		{"leading space would be trimmed", []string{` /login`}, false},
		{"trailing space would be trimmed", []string{`/login `}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := katanaCanEvaluate(tc.patterns); got != tc.want {
				t.Errorf("katanaCanEvaluate(%q) = %v, want %v", tc.patterns, got, tc.want)
			}
		})
	}
}

// runPages runs Execute against the fake katana in "pages" mode with the given
// OASM_CONFIG and returns the emitted URLs, the captured argv and the -mr/-fr
// pattern-file contents the fake saw.
func runPages(t *testing.T, config string) ([]string, []string, map[string][]string, error) {
	t.Helper()
	bin := ensureFakeKatana(t)
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args.json")
	patternsFile := filepath.Join(dir, "patterns.json")
	t.Setenv("KATANA_BIN", bin)
	t.Setenv("FAKE_MODE", "pages")
	t.Setenv("FAKE_ARGS_FILE", argsFile)
	t.Setenv("FAKE_PATTERNS_FILE", patternsFile)
	t.Setenv("OASM_CONFIG", config)

	out := make(chan connector.Finding, 64)
	err := KatanaAdapter{}.Execute(context.Background(), map[string]any{"target": "example.com"}, out)
	close(out)
	var urls []string
	for f := range out {
		urls = append(urls, f.Name)
	}

	var args []string
	if raw, readErr := os.ReadFile(argsFile); readErr == nil {
		if jsonErr := json.Unmarshal(raw, &args); jsonErr != nil {
			t.Fatalf("unmarshal captured args: %v", jsonErr)
		}
	}
	patterns := map[string][]string{}
	if raw, readErr := os.ReadFile(patternsFile); readErr == nil {
		if jsonErr := json.Unmarshal(raw, &patterns); jsonErr != nil {
			t.Fatalf("unmarshal captured patterns: %v", jsonErr)
		}
	}
	return urls, args, patterns, err
}

func flagValue(args []string, flag string) (string, bool) {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return "", false
	}
	return args[i+1], true
}

func TestKatanaExecute_PushesUrlPatternsDownAndFiltersOutput(t *testing.T) {
	urls, args, patterns, err := runPages(t, `{"matchRegex":["/login","/admin/"],"filterRegex":["\\.css$"]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The fake ignores -mr/-fr, so this proves the adapter-side filter too.
	want := []string{"https://example.com/login", "https://example.com/admin/login?next=%2F"}
	if !slices.Equal(urls, want) {
		t.Errorf("emitted URLs:\n got %v\nwant %v", urls, want)
	}

	matchFile, ok := flagValue(args, "-mr")
	if !ok {
		t.Fatalf("expected -mr in argv, got %v", args)
	}
	if _, ok := flagValue(args, "-fr"); !ok {
		t.Fatalf("expected -fr in argv, got %v", args)
	}
	if !slices.Equal(patterns["-mr"], []string{"/login", "/admin/"}) {
		t.Errorf("-mr file lines = %q", patterns["-mr"])
	}
	if !slices.Equal(patterns["-fr"], []string{`\.css$`}) {
		t.Errorf("-fr file lines = %q", patterns["-fr"])
	}
	if _, statErr := os.Stat(matchFile); !os.IsNotExist(statErr) {
		t.Errorf("pattern file %s must be removed after the run (stat err: %v)", matchFile, statErr)
	}
}

func TestKatanaExecute_KeepsPatternsKatanaWouldAlterAdapterSide(t *testing.T) {
	urls, args, _, err := runPages(t, `{"matchRegex":["#/admin"],"filterRegex":["/about"]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if slices.Contains(args, "-mr") {
		t.Errorf("a '#' pattern must not be pushed down as -mr, argv %v", args)
	}
	if !slices.Contains(args, "-fr") {
		t.Errorf("the safe filter list must still be pushed down, argv %v", args)
	}
	want := []string{"https://example.com/#/admin"}
	if !slices.Equal(urls, want) {
		t.Errorf("emitted URLs:\n got %v\nwant %v", urls, want)
	}
}

func TestKatanaExecute_WithoutPatternsEmitsEverything(t *testing.T) {
	urls, args, _, err := runPages(t, `{}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if slices.Contains(args, "-mr") || slices.Contains(args, "-fr") {
		t.Errorf("no -mr/-fr expected without patterns, argv %v", args)
	}
	if len(urls) != 5 {
		t.Errorf("expected all 5 URLs, got %v", urls)
	}
}

func TestKatanaExecute_InvalidPatternFailsBeforeStartingKatana(t *testing.T) {
	_, args, _, err := runPages(t, `{"matchRegex":["/(?=admin)"]}`)
	if err == nil {
		t.Fatal("expected an error for a non-RE2 pattern")
	}
	if !strings.Contains(err.Error(), "matchRegex[0]") {
		t.Errorf("error %q must name the offending pattern", err)
	}
	if args != nil {
		t.Errorf("katana must not be started for an invalid pattern, argv %v", args)
	}
}
