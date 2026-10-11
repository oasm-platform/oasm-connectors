//go:build e2e

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// TestFfufE2E_RealScan is the real-surface artifact: it scans a live target
// through FfufAdapter with a pinned ffuf v2.3.0 binary and the bundled
// wordlists, and writes every finding to e2e-findings.jsonl.
//
// It is build-tagged (`//go:build e2e`) so `go test ./...` never runs it. It
// fatals when FFUF_BIN is unset on purpose: the PATH ffuf on dev machines may
// be absent or stale, and a wrong version would exercise different flags.
//
// example.com legitimately yields zero directory hits with the default
// wordlist, so this asserts a clean run and URL-shaped findings — never a
// minimum finding count.
//
// Run:
//
//	FFUF_BIN=/path/to/ffuf-v2.3.0 go test -tags e2e -run TestFfufE2E_RealScan -v -count=1
func TestFfufE2E_RealScan(t *testing.T) {
	bin := os.Getenv("FFUF_BIN")
	if bin == "" {
		t.Fatalf("FFUF_BIN must be set to a pinned ffuf v2.3.0 binary")
	}
	target := os.Getenv("E2E_TARGET")
	if target == "" {
		target = "example.com"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out := make(chan connector.Finding, 1024)
	done := make(chan error, 1)
	go func() {
		done <- FfufAdapter{}.Execute(ctx, map[string]any{"target": target}, out)
		close(out)
	}()

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	if err := <-done; err != nil {
		t.Fatalf("Execute(%s) failed: %v", target, err)
	}
	for i, f := range findings {
		if !strings.HasPrefix(f.Name, "http://") && !strings.HasPrefix(f.Name, "https://") {
			t.Errorf("finding %d: Name=%q is not an http(s) URL", i, f.Name)
		}
		if f.Severity != "info" {
			t.Errorf("finding %d: Severity=%q, want info", i, f.Severity)
		}
	}

	path := filepath.Join(".", "e2e-findings.jsonl")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create %s: %v", path, err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, fd := range findings {
		rec := map[string]string{
			"name":      fd.Name,
			"severity":  fd.Severity,
			"host":      fd.Host,
			"matchedAt": fd.MatchedAt,
		}
		if err := enc.Encode(rec); err != nil {
			t.Fatalf("encode finding: %v", err)
		}
	}
	t.Logf("real scan of %s produced %d URL findings -> %s", target, len(findings), path)
}
