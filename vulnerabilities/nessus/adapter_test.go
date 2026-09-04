package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// fakeNessus is a scripted fake of the Nessus REST API. It records call counts
// and transitions scan status through a script of statuses (one per
// GET /scans/{id} call), or always returns "running" when alwaysRunning is set.
type fakeNessus struct {
	t             *testing.T
	server        *httptest.Server
	mu            sync.Mutex
	statuses      []string // status script for GET /scans/{id}
	statusIdx     int
	alwaysRunning bool

	sessionCalls int
	keysCalls    int
	statusCalls  int
	createCalls  int
	detailsCalls int
	pluginCalls  int
	deleteCalls  int
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeNessus) handleSession(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.sessionCalls++
	f.mu.Unlock()
	writeJSON(w, map[string]any{"token": "fake-token"})
}

func (f *fakeNessus) handleSessionKeys(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.keysCalls++
	f.mu.Unlock()
	writeJSON(w, map[string]any{"accessKey": "ak", "secretKey": "sk"})
}

func (f *fakeNessus) handleServerStatus(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.statusCalls++
	f.mu.Unlock()
	writeJSON(w, map[string]any{"status": "ready"})
}

func (f *fakeNessus) handleScanCreate(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.createCalls++
	f.mu.Unlock()
	writeJSON(w, map[string]any{"scan": map[string]any{"id": 1}})
}

func (f *fakeNessus) handleScanDetails(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.detailsCalls++
	var status string
	if f.alwaysRunning {
		status = "running"
	} else if len(f.statuses) == 0 {
		status = "completed"
	} else {
		idx := f.statusIdx
		if idx < len(f.statuses) {
			f.statusIdx++
		}
		if idx >= len(f.statuses) {
			idx = len(f.statuses) - 1
		}
		status = f.statuses[idx]
	}
	f.mu.Unlock()

	resp := map[string]any{
		"info": map[string]any{"status": status, "object_id": 1},
	}
	if status == "completed" {
		resp["vulnerabilities"] = []map[string]any{
			{"plugin_id": 11111, "plugin_name": "Apache Struts RCE"},
			{"plugin_id": 22222, "plugin_name": "OpenSSL Heartbleed"},
		}
	}
	writeJSON(w, resp)
}

func (f *fakeNessus) handlePluginOutput(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.pluginCalls++
	f.mu.Unlock()
	pluginID := r.PathValue("pluginID")
	writeJSON(w, map[string]any{
		"info": map[string]any{
			"plugindescription": map[string]any{
				"severity":   3,
				"pluginname": "Test Vuln " + pluginID,
				"pluginattributes": map[string]any{
					"risk_information": map[string]any{"cvss3_base_score": "9.8"},
					"synopsis":         "synopsis for " + pluginID,
					"description":      "description for " + pluginID,
					"solution":         "solution for " + pluginID,
				},
			},
		},
		"outputs": []map[string]any{
			{"ports": map[string]any{
				"443/tcp": []any{map[string]any{"hostname": "example.com", "port": "443"}},
			}},
		},
	})
}

func (f *fakeNessus) handleScanDelete(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.deleteCalls++
	f.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func newFakeNessus(t *testing.T, statuses ...string) *fakeNessus {
	t.Helper()
	f := &fakeNessus{t: t, statuses: statuses}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /session", f.handleSession)
	mux.HandleFunc("PUT /session/keys", f.handleSessionKeys)
	mux.HandleFunc("GET /server/status", f.handleServerStatus)
	mux.HandleFunc("POST /scans", f.handleScanCreate)
	mux.HandleFunc("GET /scans/{id}", f.handleScanDetails)
	mux.HandleFunc("GET /scans/{id}/plugins/{pluginID}", f.handlePluginOutput)
	mux.HandleFunc("DELETE /scans/{id}", f.handleScanDelete)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func setNessusEnv(t *testing.T, url string) {
	t.Helper()
	t.Setenv("NESSUS_URL", url)
	t.Setenv("NESSUS_USERNAME", "user")
	t.Setenv("NESSUS_PASSWORD", "pass")
	t.Setenv("NESSUS_ACCESS_KEY", "ak")
	t.Setenv("NESSUS_SECRET_KEY", "sk")
	t.Setenv("NESSUS_TEMPLATE_UUID", "")
	t.Setenv("NESSUS_POLICY_ID", "")
	t.Setenv("NESSUS_FOLDER_ID", "")
	t.Setenv("EXECUTION_ID", "test-exec")
}

// shortenPoll speeds up poll-loop tests; cleanup restores the production value.
func shortenPoll(t *testing.T, d time.Duration) {
	t.Helper()
	old := pollInterval
	pollInterval = d
	t.Cleanup(func() { pollInterval = old })
}

func TestValidate_NoOp(t *testing.T) {
	a := NessusAdapter{}
	inputs := []map[string]any{
		nil,
		{},
		{"target": "10.0.0.1"},
		{"target": 42, "extra": "x"},
	}
	for _, in := range inputs {
		if err := a.Validate(context.Background(), in); err != nil {
			t.Errorf("Validate(%v) = %v, want nil", in, err)
		}
	}
}

func TestExecute_MissingTarget(t *testing.T) {
	a := NessusAdapter{}
	err := a.Execute(context.Background(), map[string]any{}, make(chan connector.Finding, 1))
	if err == nil || !strings.Contains(err.Error(), "target required") {
		t.Fatalf("err = %v, want error containing 'target required'", err)
	}
}

func TestExecute_MissingURL(t *testing.T) {
	t.Setenv("NESSUS_URL", "")
	t.Setenv("NESSUS_USERNAME", "u")
	t.Setenv("NESSUS_PASSWORD", "p")
	a := NessusAdapter{}
	err := a.Execute(context.Background(), map[string]any{"target": "10.0.0.1"}, make(chan connector.Finding, 1))
	if err == nil {
		t.Fatal("want error for missing NESSUS_URL")
	}
}

func TestExecute_HappyPath(t *testing.T) {
	f := newFakeNessus(t, "running", "completed")
	setNessusEnv(t, f.server.URL)
	shortenPoll(t, 20*time.Millisecond)

	out := make(chan connector.Finding, 16)
	if err := (&NessusAdapter{}).Execute(context.Background(), map[string]any{"target": "10.0.0.1"}, out); err != nil {
		t.Fatalf("Execute error: %v", err)
	}
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}

	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	names := map[string]bool{}
	for _, finding := range findings {
		names[finding.Name] = true
	}
	if !names["Test Vuln 11111"] || !names["Test Vuln 22222"] {
		t.Errorf("findings missing expected plugin findings 11111/22222: %v", names)
	}
	// Fake data severity 3 → high, Host from the port output map.
	for _, finding := range findings {
		if finding.Severity != "high" {
			t.Errorf("finding %q severity = %q, want high", finding.Name, finding.Severity)
		}
		if finding.Host != "example.com" {
			t.Errorf("finding %q host = %q, want example.com", finding.Name, finding.Host)
		}
		if err := finding.Validate(); err != nil {
			t.Errorf("finding %q invalid: %v", finding.Name, err)
		}
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteCalls != 1 {
		t.Errorf("deleteCalls = %d, want 1 (cleanup ran)", f.deleteCalls)
	}
	if f.sessionCalls != 1 {
		t.Errorf("sessionCalls = %d, want 1", f.sessionCalls)
	}
	if f.keysCalls != 1 {
		t.Errorf("keysCalls = %d, want 1", f.keysCalls)
	}
	if f.createCalls != 1 {
		t.Errorf("createCalls = %d, want 1", f.createCalls)
	}
	if f.pluginCalls != 2 {
		t.Errorf("pluginCalls = %d, want 2", f.pluginCalls)
	}
}

func TestExecute_ScanAborted(t *testing.T) {
	f := newFakeNessus(t, "running", "aborted")
	setNessusEnv(t, f.server.URL)
	shortenPoll(t, 20*time.Millisecond)

	out := make(chan connector.Finding, 16)
	err := (&NessusAdapter{}).Execute(context.Background(), map[string]any{"target": "10.0.0.1"}, out)
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("err = %v, want error containing 'aborted'", err)
	}
	if len(out) != 0 {
		t.Errorf("out = %d findings, want 0", len(out))
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteCalls != 0 {
		t.Errorf("deleteCalls = %d, want 0 (retention on failure)", f.deleteCalls)
	}
}

func TestExecute_ServerUnreachable(t *testing.T) {
	f := newFakeNessus(t, "completed")
	url := f.server.URL
	f.server.Close() // close the listener; connection refused

	setNessusEnv(t, url)

	err := (&NessusAdapter{}).Execute(context.Background(), map[string]any{"target": "10.0.0.1"}, make(chan connector.Finding, 16))
	if err == nil {
		t.Fatal("want error for unreachable server")
	}
}

func TestExecute_CtxCancelMidPoll(t *testing.T) {
	f := newFakeNessus(t)
	f.alwaysRunning = true
	setNessusEnv(t, f.server.URL)
	shortenPoll(t, 20*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan connector.Finding, 16)
	done := make(chan error, 1)
	go func() {
		done <- (&NessusAdapter{}).Execute(ctx, map[string]any{"target": "10.0.0.1"}, out)
	}()

	// Wait until the fake server has served at least one details poll.
	deadline := time.Now().Add(2 * time.Second)
	for {
		f.mu.Lock()
		calls := f.detailsCalls
		f.mu.Unlock()
		if calls >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for first poll")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Execute did not return after cancel")
	}

	if len(out) != 0 {
		t.Errorf("out = %d findings, want 0", len(out))
	}
}
