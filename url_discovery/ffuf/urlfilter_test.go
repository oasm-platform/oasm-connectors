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
	return collect(t, "default", "example.com")
}

// The adapter reports only URLs matching any matchRegex pattern and no
// filterRegex pattern (shared url_discovery semantics, see connector.URLFilter).
// ffuf's own -mr/-fr match the response body, not the URL, so the adapter
// filters its output.
func TestFfufExecute_AppliesUrlPatterns(t *testing.T) {
	findings, err := collectWithConfig(t, `{"matchRegex":["/(one|three)$"],"filterRegex":["three"]}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []string
	for _, f := range findings {
		got = append(got, f.Name)
	}
	if want := []string{"https://example.com/one"}; !slices.Equal(got, want) {
		t.Errorf("emitted URLs:\n got %v\nwant %v", got, want)
	}
}

func TestFfufExecute_InvalidUrlPatternErrors(t *testing.T) {
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
func TestFfufExecute_UsesPerJobConfigFromContext(t *testing.T) {
	t.Setenv("FFUF_BIN", ensureFakeFfuf(t))
	t.Setenv("FAKE_MODE", "default")
	t.Setenv("OASM_CONFIG", `{"matchRegex":["/two$"]}`)
	ctx := connector.WithConfig(context.Background(), `{"matchRegex":["/one$"]}`)

	out := make(chan connector.Finding, 64)
	err := FfufAdapter{}.Execute(ctx, map[string]any{"target": "example.com"}, out)
	close(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got []string
	for f := range out {
		got = append(got, f.Name)
	}
	if want := []string{"https://example.com/one"}; !slices.Equal(got, want) {
		t.Errorf("emitted URLs:\n got %v\nwant %v", got, want)
	}
}
