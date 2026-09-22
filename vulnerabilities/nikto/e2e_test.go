//go:build e2e

package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// TestNiktoE2E_RealScan runs the adapter against a REAL nikto. NIKTO_BIN must
// point at a nikto.pl binary (or a wrapper around one); the target must be
// reachable from wherever that binary runs. No fake, no fixture — this is the
// only test that proves the argv vector, the generated config, the stdout
// parser and the db_tests enrichment all agree with the shipped tool.
//
//	docker network create oasm-nikto-e2e
//	docker run -d --name nikto-target --network oasm-nikto-e2e nginx:alpine
//	E2E_TARGET=http://nikto-target NIKTO_BIN=<nikto.pl or wrapper> \
//	  go test -tags e2e -run TestNiktoE2E_RealScan -v -count=1
func TestNiktoE2E_RealScan(t *testing.T) {
	bin := os.Getenv("NIKTO_BIN")
	if bin == "" {
		t.Fatal("NIKTO_BIN must point at a real nikto.pl (this test never runs a fake)")
	}
	target := os.Getenv("E2E_TARGET")
	if target == "" {
		target = "http://nikto-target"
	}

	// Tuning 236 adds the CGI/DoS and misconfiguration checks, so a real scan
	// exercises ids that exist in db_tests (000024, 007342, 007352) alongside
	// the plugin-only header ids (013587) that must fall back to keywords.
	t.Setenv("OASM_CONFIG", `{"tuning":"236","maxTime":"120s"}`)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out := make(chan connector.Finding, 256)
	err := NiktoAdapter{}.Execute(ctx, map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from a real scan")
	}
	for i, f := range findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d invalid: %v", i, err)
		}
		if f.Name == "" {
			t.Errorf("finding %d has an empty name", i)
		}
	}

	// Report what the database enrichment recovered. Every finding must carry a
	// severity-source tag, and at least one must be categorised from db_tests —
	// otherwise the enrichment silently did nothing (e.g. the database was not
	// found next to NIKTO_BIN).
	t.Logf("db_tests loaded: %v", loadNiktoDB() != nil)
	categorised, withCVE := 0, 0
	for _, f := range findings {
		hasSource := false
		for _, tag := range f.Tags {
			if strings.HasPrefix(tag, "category:") {
				categorised++
				break
			}
		}
		for _, tag := range f.Tags {
			if strings.HasPrefix(tag, "severity-source:") {
				hasSource = true
			}
		}
		if !hasSource {
			t.Errorf("finding %q has no severity-source tag: %v", f.Name, f.Tags)
		}
		if len(f.CVEID) > 0 {
			withCVE++
			t.Logf("  CVE recovered: %v <- %s", f.CVEID, f.Name)
		}
	}
	t.Logf("real scan produced %d findings; first: %q (%s); %d categorised from db_tests; %d with CVEs",
		len(findings), findings[0].Name, findings[0].Severity, categorised, withCVE)
}
