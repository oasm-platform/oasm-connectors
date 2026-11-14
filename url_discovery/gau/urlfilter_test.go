package main

import (
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
func TestGauExecute_AppliesUrlPatterns(t *testing.T) {
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

func TestGauExecute_InvalidUrlPatternErrors(t *testing.T) {
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
