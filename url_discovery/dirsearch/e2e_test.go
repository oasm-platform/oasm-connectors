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

// TestDirsearchE2E_RealScan is the real-surface artifact: it runs a live target
// through DirsearchAdapter with a pinned dirsearch 0.5.0 binary and writes every
// finding to e2e-findings.jsonl.
//
// It is build-tagged (`//go:build e2e`) so `go test ./...` never runs it. It
// fatals when DIRSEARCH_BIN is unset on purpose: the connector must be exercised
// against the pinned 0.5.0 install, not whatever dirsearch a dev machine has.
//
// It asserts a clean run (nil error) and that every finding is an http(s) URL.
// It does NOT assert a minimum finding count: example.com legitimately yields
// zero hits, so a zero-finding run is a valid pass.
//
// Run:
//
//	DIRSEARCH_BIN=/path/to/dirsearch go test -tags e2e -run TestDirsearchE2E_RealScan -v -count=1
func TestDirsearchE2E_RealScan(t *testing.T) {
	bin := os.Getenv("DIRSEARCH_BIN")
	if bin == "" {
		t.Fatalf("DIRSEARCH_BIN must be set to a pinned dirsearch 0.5.0 binary")
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
		done <- DirsearchAdapter{}.Execute(ctx, map[string]any{"target": target}, out)
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
	t.Logf("real scan of %s produced %d unique URL findings -> %s", target, len(findings), path)
}
