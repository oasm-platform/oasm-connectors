package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// TestE2E_RealZap drives a real ZAP install through the adapter. It is skipped
// unless ZAP_E2E_TARGET is set, so the normal test run needs neither ZAP nor
// network:
//
//	# any OS with zap.sh on PATH
//	ZAP_E2E_TARGET=https://example.com go test -run TestE2E_RealZap -v -count=1 -timeout 30m
//
//	# Windows (ZAP installer), point ZAP_BIN at the bat file
//	set ZAP_E2E_TARGET=https://example.com
//	set ZAP_BIN=C:\Program Files\ZAP\Zed Attack Proxy\zap.bat
//	go test -run TestE2E_RealZap -v -count=1 -timeout 30m
//
// baseline mode is safe (spider + passive scan only). A target with obvious
// missing security headers (e.g. https://example.com) yields at least one
// finding, which is what the test asserts.
func TestE2E_RealZap(t *testing.T) {
	target := os.Getenv("ZAP_E2E_TARGET")
	if target == "" {
		t.Skip("set ZAP_E2E_TARGET to run a real ZAP scan")
	}
	// Default to the safe passive-only profile; override OASM_CONFIG to try
	// scanMode=full or other settings.
	if strings.TrimSpace(os.Getenv("OASM_CONFIG")) == "" {
		t.Setenv("OASM_CONFIG", `{"scanMode":"baseline"}`)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	out := make(chan connector.Finding, 256)
	done := make(chan error, 1)
	go func() {
		done <- (&ZapAdapter{}).Execute(ctx, map[string]any{"target": target}, out)
		close(out)
	}()

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	if err := <-done; err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(findings) == 0 {
		t.Fatalf("expected at least one finding from %s", target)
	}
	for i, f := range findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d failed SDK validation: %v", i, err)
		}
		if i < 5 {
			t.Logf("finding: %-45s sev=%s host=%s", f.Name, f.Severity, f.Host)
		}
	}
	t.Logf("streamed %d findings from %s", len(findings), target)
}
