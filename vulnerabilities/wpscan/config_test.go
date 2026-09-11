package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// captureArgs runs Execute against the fake wpscan with the given OASM_CONFIG
// JSON and returns the exact arg vector (os.Args[1:]) the process received.
func captureArgs(t *testing.T, cfgJSON string) []string {
	t.Helper()
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", cfgJSON)

	argsFile := filepath.Join(t.TempDir(), "args.json")
	t.Setenv("FAKE_ARGS_FILE", argsFile)

	out := make(chan connector.Finding, 64)
	err := WpscanAdapter{}.Execute(context.Background(), map[string]any{"target": "https://example.com"}, out)
	close(out)
	if err != nil {
		t.Fatalf("unexpected execute error: %v", err)
	}

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	var args []string
	if err := json.Unmarshal(raw, &args); err != nil {
		t.Fatalf("decode captured args: %v", err)
	}
	return args
}

func TestWpscanExecute_DefaultArgs(t *testing.T) {
	got := captureArgs(t, "")
	want := []string{"--url", "https://example.com", "--format", "json", "--no-banner"}
	if len(got) != len(want) {
		t.Fatalf("default args len = %d (%v), want %d (%v)", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("default args[%d] = %q, want %q (full: %v)", i, got[i], want[i], got)
		}
	}
}

func TestWpscanExecute_MapsConfigToFlags(t *testing.T) {
	cfg := `{"force":true,"stealthy":true,"apiToken":"tok","enumerate":["vp","vt","u"],"pluginsDetection":"mixed","maxThreads":10,"proxy":"http://127.0.0.1:8080","update":false}`
	args := captureArgs(t, cfg)
	t.Logf("captured args: %v", args)

	// Prefix must be preserved.
	prefix := []string{"--url", "https://example.com", "--format", "json", "--no-banner"}
	if len(args) < len(prefix) {
		t.Fatalf("args shorter than prefix: %v", args)
	}
	for i := range prefix {
		if args[i] != prefix[i] {
			t.Fatalf("prefix[%d] = %q, want %q (full: %v)", i, args[i], prefix[i], args)
		}
	}

	joined := " " + joinArgs(args) + " "
	for _, want := range []string{
		" --force ",
		" --stealthy ",
		" --api-token tok ",
		" -e vp,vt,u ",
		" --plugins-detection mixed ",
		" --max-threads 10 ",
		" --proxy http://127.0.0.1:8080 ",
		" --no-update ",
	} {
		if !contains(joined, want) {
			t.Errorf("missing %q in args %v", want, args)
		}
	}
}

func TestWpscanExecute_InvalidConfigErrors(t *testing.T) {
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", "{bad json")

	out := make(chan connector.Finding, 64)
	err := WpscanAdapter{}.Execute(context.Background(), map[string]any{"target": "https://example.com"}, out)
	close(out)
	if err == nil {
		t.Fatal("expected error for invalid OASM_CONFIG")
	}
	if !contains(err.Error(), "invalid OASM_CONFIG") {
		t.Fatalf("expected 'invalid OASM_CONFIG' in error, got: %s", err.Error())
	}
}

func TestBuildWpscanArgs_UpdateTriState(t *testing.T) {
	hasFlag := func(args []string, flag string) bool {
		for _, a := range args {
			if a == flag {
				return true
			}
		}
		return false
	}

	unset := buildWpscanArgs("https://example.com", &wpscanConfig{})
	if hasFlag(unset, "--update") || hasFlag(unset, "--no-update") {
		t.Fatalf("nil update should emit neither flag, got %v", unset)
	}

	yes := true
	enabled := buildWpscanArgs("https://example.com", &wpscanConfig{Update: &yes})
	if !hasFlag(enabled, "--update") {
		t.Fatalf("update=true should emit --update, got %v", enabled)
	}

	no := false
	disabled := buildWpscanArgs("https://example.com", &wpscanConfig{Update: &no})
	if !hasFlag(disabled, "--no-update") {
		t.Fatalf("update=false should emit --no-update, got %v", disabled)
	}
}

func TestLoadWpscanConfig_EmptyIsNoop(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadWpscanConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil zero config")
	}
}

// joinArgs renders an arg vector as a single space-separated string so the
// presence assertions above can match multi-token flags.
func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
