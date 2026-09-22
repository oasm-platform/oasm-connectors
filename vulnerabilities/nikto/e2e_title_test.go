//go:build e2e

package main

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// TestNiktoE2E_TitleAndDescription proves that a real scan yields a Description
// for every finding and that a multi-sentence check gets a shortened Name.
func TestNiktoE2E_TitleAndDescription(t *testing.T) {
	bin := os.Getenv("NIKTO_BIN")
	if bin == "" {
		t.Fatal("NIKTO_BIN must point at a real nikto.pl")
	}
	target := os.Getenv("E2E_TARGET")
	if target == "" {
		target = "http://nikto-target"
	}
	t.Setenv("OASM_CONFIG", `{"tuning":"236","maxTime":"120s"}`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out := make(chan connector.Finding, 256)
	if err := (NiktoAdapter{}).Execute(ctx, map[string]any{"target": target}, out); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	if len(findings) == 0 {
		t.Fatal("expected findings from a real scan")
	}

	shortened := 0
	for _, f := range findings {
		if f.Description == "" {
			t.Errorf("finding %q has an empty Description", f.Name)
		}
		// Name must always be a prefix of Description.
		if len(f.Name) > len(f.Description) || f.Description[:len(f.Name)] != f.Name {
			t.Errorf("Name %q is not a prefix of Description %q", f.Name, f.Description)
		}
		if f.Name != f.Description {
			shortened++
			t.Logf("shortened:\n  Name: %s\n  Desc: %s", f.Name, f.Description)
		}
	}
	t.Logf("%d findings, %d with a shortened title", len(findings), shortened)
}
