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

// TestKatanaE2E_RealCrawl is the real-surface artifact: it crawls a live target
// through KatanaAdapter with a pinned katana v1.7.0 binary, and writes every
// finding to e2e-findings.jsonl.
//
// It is build-tagged (`//go:build e2e`) so `go test ./...` never runs it. It
// fatals when KATANA_BIN is unset on purpose: the PATH katana on dev machines is
// often stale (v1.2.1 here) and lacks -duc/-mdp/-fsu, which would fail with
// exit 2 rather than exercise the adapter.
//
// Run:
//
//	KATANA_BIN=/path/to/katana-v1.7.0 go test -tags e2e -run TestKatanaE2E_RealCrawl -v -count=1
func TestKatanaE2E_RealCrawl(t *testing.T) {
	bin := os.Getenv("KATANA_BIN")
	if bin == "" {
		t.Fatalf("KATANA_BIN must be set to a pinned katana v1.7.0 binary")
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
		done <- KatanaAdapter{}.Execute(ctx, map[string]any{"target": target}, out)
		close(out)
	}()

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	if err := <-done; err != nil {
		t.Fatalf("Execute(%s) failed: %v", target, err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected at least 1 finding from a real crawl of %s", target)
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
	t.Logf("real crawl of %s produced %d unique URL findings -> %s", target, len(findings), path)
}
