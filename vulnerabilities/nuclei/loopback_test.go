package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// writeTemplate writes a YAML template file into dir and returns its path.
func writeTemplate(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write template %s: %v", name, err)
	}
	return path
}

// setupLoopboxEnv configures env vars so the adapter resolves templates from
// tmplDir and does not write config files to the real user home.
func setupLoopbackEnv(t *testing.T, tmplDir string) {
	t.Helper()
	t.Setenv("NUCLEI_TEMPLATE_DIR", tmplDir)
	t.Setenv("NUCLEI_TEMPLATES_DIR", "")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("OASM_CONFIG", "")
}

// TestExecute_LoopbackScan proves the in-process nuclei engine scans a local
// HTTP target and emits findings. Four sub-cases cover: matching template,
// no-match template, sentinel error (template ID not found), and context
// cancellation.
func TestExecute_LoopbackScan(t *testing.T) {
	a := &NucleiAdapter{}

	// ── Sub-case A: matching template (happy path) ──────────────────────────
	t.Run("matching", func(t *testing.T) {
		var reqCount atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqCount.Add(1)
			w.Header().Set("X-Probe-Header", "hit")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		}))
		defer srv.Close()

		tmplDir := t.TempDir()
		writeTemplate(t, tmplDir, "probe.yaml", `id: loopback-probe
info:
  name: Loopback Probe
  author: oasm-test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        dsl:
          - status_code == 200
`)
		setupLoopbackEnv(t, tmplDir)

		ctx := context.Background()
		ch := make(chan connector.Finding, 64)
		err := a.Execute(ctx, map[string]any{"target": srv.URL}, ch)
		close(ch)

		var findings []connector.Finding
		for f := range ch {
			findings = append(findings, f)
		}

		if err != nil {
			t.Fatalf("Execute returned error: %v", err)
		}
		if len(findings) == 0 {
			t.Fatal("expected at least 1 finding, got 0")
		}

		count := int(reqCount.Load())
		if count == 0 {
			t.Fatal("expected at least 1 HTTP request to the test server, got 0")
		}
		t.Logf("matching: %d finding(s), %d request(s)", len(findings), count)

		f := findings[0]
		if f.Name == "" {
			t.Error("finding Name must not be empty")
		}
		if f.MatchedAt == "" {
			t.Error("finding MatchedAt must not be empty")
		}
		// MatchedAt should reference the server host.
		host := strings.TrimPrefix(srv.URL, "http://")
		if !strings.Contains(f.MatchedAt, host) {
			t.Errorf("MatchedAt = %q, want to contain host %q", f.MatchedAt, host)
		}
	})

	// ── Sub-case B: no-match template ───────────────────────────────────────
	t.Run("no_match", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		}))
		defer srv.Close()

		tmplDir := t.TempDir()
		// Template matches on a header the server never sends.
		writeTemplate(t, tmplDir, "no-match.yaml", `id: never-match
info:
  name: Never Match
  author: oasm-test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - "X-Never-Match: yes"
        part: header
`)
		setupLoopbackEnv(t, tmplDir)

		ctx := context.Background()
		ch := make(chan connector.Finding, 64)
		err := a.Execute(ctx, map[string]any{"target": srv.URL}, ch)
		close(ch)

		var findings []connector.Finding
		for f := range ch {
			findings = append(findings, f)
		}

		if err != nil {
			t.Fatalf("Execute returned error: %v", err)
		}
		if len(findings) != 0 {
			t.Fatalf("expected 0 findings for non-matching template, got %d", len(findings))
		}
		t.Log("no_match: 0 findings as expected")
	})

	// ── Sub-case C: sentinel error (no templates available) ─────────────────
	t.Run("no_templates", func(t *testing.T) {
		tmplDir := t.TempDir()
		writeTemplate(t, tmplDir, "dummy.yaml", `id: dummy-probe
info:
  name: Dummy Probe
  author: oasm-test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        dsl:
          - status_code == 200
`)
		setupLoopbackEnv(t, tmplDir)
		// Filter to a template ID that does not exist.
		t.Setenv("OASM_CONFIG", `{"templateIds":["definitely-not-a-real-template-id"]}`)

		ctx := context.Background()
		ch := make(chan connector.Finding, 64)
		err := a.Execute(ctx, map[string]any{"target": "http://127.0.0.1:1"}, ch)
		close(ch)

		var findings []connector.Finding
		for f := range ch {
			findings = append(findings, f)
		}
		_ = findings

		if err == nil {
			t.Fatal("expected error for non-existent template ID, got nil")
		}
		if !strings.Contains(err.Error(), "no templates available") {
			t.Fatalf("error = %q, want substring 'no templates available'", err.Error())
		}
		t.Logf("no_templates: error=%q", err.Error())
	})

	// ── Sub-case D: context cancellation ────────────────────────────────────
	t.Run("ctx_cancel", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		}))
		defer srv.Close()

		tmplDir := t.TempDir()
		writeTemplate(t, tmplDir, "probe.yaml", `id: loopback-probe-cancel
info:
  name: Loopback Probe Cancel
  author: oasm-test
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: dsl
        dsl:
          - status_code == 200
`)
		setupLoopbackEnv(t, tmplDir)

		ctx, cancel := context.WithCancel(context.Background())
		// Cancel after a short delay to race with the scan.
		time.AfterFunc(100*time.Millisecond, cancel)

		ch := make(chan connector.Finding, 64)
		done := make(chan error, 1)
		go func() {
			done <- a.Execute(ctx, map[string]any{"target": srv.URL}, ch)
		}()

		select {
		case err := <-done:
			if err != nil && ctx.Err() != nil {
				t.Logf("ctx_cancel: Execute returned (ctx cancelled): %v", err)
			} else {
				t.Logf("ctx_cancel: Execute returned cleanly: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("ctx_cancel: Execute did not return within 5s after context cancellation")
		}
	})
}
