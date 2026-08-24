package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
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
	out := make(chan []byte, 64)
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
	out := make(chan []byte, 64)
	ctx := context.Background()

	err := a.Execute(ctx, map[string]any{"target": "https://example.com"}, out)
	close(out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var findings []map[string]any
	for raw := range out {
		var f map[string]any
		if err := unmarshalJSON(raw, &f); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		findings = append(findings, f)
	}

	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}

	// Check first finding (core vulnerability).
	title0, _ := findings[0]["title"].(string)
	if title0 != "XSS in Search Form" {
		t.Errorf("expected first finding title 'XSS in Search Form', got %q", title0)
	}

	// Check second finding (plugin vulnerability).
	title1, _ := findings[1]["title"].(string)
	if title1 != "Open Redirect in Akismet" {
		t.Errorf("expected second finding title 'Open Redirect in Akismet', got %q", title1)
	}
}

func TestWpscanExecute_EmptyOutputNoError(t *testing.T) {
	bin := ensureFakeWpscan(t)
	t.Setenv("WPSCAN_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")

	a := WpscanAdapter{}
	out := make(chan []byte, 64)
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
	out := make(chan []byte, 64)
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

// unmarshalJSON is a test helper that uses encoding/json.
func unmarshalJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}
