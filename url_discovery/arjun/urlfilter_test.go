package main

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

func collectWithConfig(t *testing.T, config string) ([]connector.Finding, error) {
	t.Helper()
	t.Setenv("OASM_CONFIG", config)
	return collect(t, "default", "https://example.com/")
}

// The adapter reports only URLs matching any matchRegex pattern and no
// filterRegex pattern (shared url_discovery semantics, see connector.URLFilter).
// The patterns see the emitted "<url>?<param>=" form.
func TestArjunExecute_AppliesUrlPatterns(t *testing.T) {
	findings, err := collectWithConfig(t, `{"matchRegex":["[?&](id|redirect)="],"filterRegex":["[?&]id="]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []string
	for _, f := range findings {
		got = append(got, f.Name)
	}
	if want := []string{"https://example.com/?redirect="}; !slices.Equal(got, want) {
		t.Errorf("emitted URLs:\n got %v\nwant %v", got, want)
	}
}

func TestArjunExecute_InvalidUrlPatternErrors(t *testing.T) {
	findings, err := collectWithConfig(t, `{"matchRegex":["("]}`)
	if err == nil {
		t.Fatal("expected an error for an invalid pattern")
	}
	if !strings.Contains(err.Error(), "matchRegex[0]") {
		t.Errorf("error %q must name the offending pattern", err)
	}
	if len(findings) != 0 {
		t.Errorf("no findings expected, got %d", len(findings))
	}
}

// A warm-pool container keeps its first run's OASM_CONFIG env; the runtime
// ships each job's own config on ctx, and that config must win.
func TestArjunExecute_UsesPerJobConfigFromContext(t *testing.T) {
	t.Setenv("ARJUN_BIN", ensureFakeArjun(t))
	t.Setenv("FAKE_MODE", "default")
	t.Setenv("OASM_CONFIG", `{"matchRegex":["[?&]redirect="]}`)
	ctx := connector.WithConfig(context.Background(), `{"matchRegex":["[?&]id="]}`)

	out := make(chan connector.Finding, 64)
	err := ArjunAdapter{}.Execute(ctx, map[string]any{"target": "https://example.com/"}, out)
	close(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []string
	for f := range out {
		got = append(got, f.Name)
	}
	if want := []string{"https://example.com/?id="}; !slices.Equal(got, want) {
		t.Errorf("emitted URLs:\n got %v\nwant %v", got, want)
	}
}
