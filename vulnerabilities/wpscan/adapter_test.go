package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

var (
	fakeWpscanPath string
	fakeOnce       sync.Once
)

// ensureFakeWpscan builds the fake wpscan binary once for the test run.
// Uses os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeWpscan(t *testing.T) string {
	t.Helper()
	fakeOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-wpscan-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeWpscanPath = filepath.Join(dir, "fake-wpscan"+ext)
		cmd := exec.Command("go", "build", "-o", fakeWpscanPath, "./testdata/fake-wpscan")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build fake-wpscan: %v\n%s", err, out)
		}
	})
	return fakeWpscanPath
}

func TestValidate_IsNoOp(t *testing.T) {
	a := WpscanAdapter{}
	if err := a.Validate(context.Background(), nil); err != nil {
		t.Fatalf("Validate should return nil, got %v", err)
	}
}

func TestWpscanExecute_MissingTargetErrors(t *testing.T) {
	a := WpscanAdapter{}
	out := make(chan connector.Finding, 64)
	err := a.Execute(context.Background(), map[string]any{}, out)
	close(out)
	if err == nil {
		t.Fatal("expected error for missing target")
	}
	if !contains(err.Error(), "target required") {
		t.Fatalf("expected 'target required' in error, got: %s", err.Error())
	}
}

func TestWpscanExecute_StreamsJsonlFindings(t *testing.T) {
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)

	a := WpscanAdapter{}
	out := make(chan connector.Finding, 64)
	ctx := context.Background()

	err := a.Execute(ctx, map[string]any{"target": "https://example.com"}, out)
	close(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check first finding (core vulnerability).
	if findings[0].Name != "XSS in Search Form" {
		t.Errorf("expected first finding name 'XSS in Search Form', got %q", findings[0].Name)
	}
	if findings[0].MatchedAt != "https://example.com" {
		t.Errorf("expected first finding MatchedAt 'https://example.com', got %q", findings[0].MatchedAt)
	}

	// Check second finding (plugin vulnerability).
	if findings[1].Name != "Open Redirect in Akismet" {
		t.Errorf("expected second finding name 'Open Redirect in Akismet', got %q", findings[1].Name)
	}

	// Every emitted Finding must pass the SDK contract validation.
	for i, f := range findings {
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d invalid: %v", i, err)
		}
	}
}

func TestWpscanExecute_EmptyOutputNoError(t *testing.T) {
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")

	a := WpscanAdapter{}
	out := make(chan connector.Finding, 64)
	ctx := context.Background()

	err := a.Execute(ctx, map[string]any{"target": "https://clean.example.com"}, out)
	close(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	count := 0
	for range out {
		count++
	}
	if count != 0 {
		t.Fatalf("expected 0 findings, got %d", count)
	}
}

func TestWpscanExecute_ReturnsErrorOnNonZeroExit(t *testing.T) {
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)
	t.Setenv("FAKE_MODE", "fail")

	a := WpscanAdapter{}
	out := make(chan connector.Finding, 64)
	ctx := context.Background()

	err := a.Execute(ctx, map[string]any{"target": "https://example.com"}, out)
	close(out)
	if err == nil {
		t.Fatal("expected error on non-zero exit")
	}
	if !contains(err.Error(), "connection refused") {
		t.Fatalf("expected 'connection refused' in error, got: %s", err.Error())
	}
}

// --- helpers ---

func contains(s, substr string) bool {
	return len(s) >= len(substr) && searchString(s, substr)
}

func searchString(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
