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

// TestArjunE2E_RealDiscovery is the real-surface artifact: it probes a live
// target through ArjunAdapter with a pinned arjun 2.2.7 binary and writes every
// finding to e2e-findings.jsonl.
//
// It is build-tagged (`//go:build e2e`) so `go test ./...` never runs it. It
// fatals when ARJUN_BIN or E2E_TARGET is unset on purpose: the connector's
// ARJUN_BIN env must point at the pinned 2.2.7 install (its bundled
// db/small|medium|large.txt feed the -w shortcut), and a real network target is
// required to exercise the adapter end to end.
//
// Zero findings is a clean success (Arjun writes no output file when it finds
// nothing), so this test asserts a clean run and validates the <url>?<param>=
// shape of any findings emitted.
//
// Run:
//
//	ARJUN_BIN=/usr/local/bin/arjun E2E_TARGET=https://example.com/ \
//	  go test -tags e2e -run TestArjunE2E_RealDiscovery -v -count=1
func TestArjunE2E_RealDiscovery(t *testing.T) {
	bin := os.Getenv("ARJUN_BIN")
	if bin == "" {
		t.Fatalf("ARJUN_BIN must be set to a pinned arjun 2.2.7 binary")
	}
	target := os.Getenv("E2E_TARGET")
	if target == "" {
		t.Fatalf("E2E_TARGET must be set to a live target URL")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	out := make(chan connector.Finding, 1024)
	done := make(chan error, 1)
	go func() {
		done <- ArjunAdapter{}.Execute(ctx, map[string]any{"target": target}, out)
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
		if !strings.Contains(f.Name, "?") && !strings.Contains(f.Name, "&") {
			t.Errorf("finding %d: Name=%q is not <url>?<param>=", i, f.Name)
		}
		if !strings.HasSuffix(f.Name, "=") {
			t.Errorf("finding %d: Name=%q does not end in '=' (Arjun emits <url>?<param>=)", i, f.Name)
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
	t.Logf("real discovery on %s produced %d parameter findings -> %s", target, len(findings), path)
}
