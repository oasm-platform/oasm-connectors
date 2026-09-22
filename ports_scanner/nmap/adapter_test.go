package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

var (
	fakeNmapPath string
	fakeNmapOnce sync.Once
)

// ensureFakeNmap builds the fake nmap binary once for the test run. Uses
// os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeNmap(t *testing.T) string {
	t.Helper()
	fakeNmapOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-nmap-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeNmapPath = filepath.Join(dir, "fake-nmap"+ext)
		cmd := exec.Command("go", "build", "-o", fakeNmapPath, "./testdata/fake-nmap")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build fake-nmap: %v\n%s", err, out)
		}
	})
	return fakeNmapPath
}

// collect runs Execute against the fake nmap with FAKE_MODE=mode and returns the
// emitted findings plus the returned error.
func collect(t *testing.T, mode, target string) ([]connector.Finding, error) {
	t.Helper()
	t.Setenv("NMAP_BIN", ensureFakeNmap(t))
	t.Setenv("FAKE_MODE", mode)

	out := make(chan connector.Finding, 64)
	err := NmapAdapter{}.Execute(context.Background(), map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

func TestLoadNmapConfig_UnsetIsZeroConfig(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadNmapConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Ports != "" || cfg.TopPorts != 0 || cfg.HostTimeout != 0 || cfg.Retries != 0 || cfg.NoPing != nil {
		t.Fatalf("expected zero config, got %+v", cfg)
	}
}

func TestLoadNmapConfig_ParsesAndRejects(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"ports":"22,80","topPorts":100,"hostTimeout":300,"retries":2,"noPing":false}`)
	cfg, err := loadNmapConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Ports != "22,80" || cfg.TopPorts != 100 || cfg.HostTimeout != 300 || cfg.Retries != 2 ||
		cfg.NoPing == nil || *cfg.NoPing {
		t.Fatalf("config not parsed: %+v", cfg)
	}
	if noPingEnabled(cfg) {
		t.Fatal("explicit noPing=false must disable -Pn")
	}
	// An omitted noPing must stay nil so the adapter keeps the -Pn default.
	t.Setenv("OASM_CONFIG", `{"topPorts":10}`)
	omitted, err := loadNmapConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if omitted.NoPing != nil || !noPingEnabled(omitted) {
		t.Fatalf("omitted noPing must default to -Pn, got %+v", omitted)
	}

	t.Setenv("OASM_CONFIG", "{not json")
	if _, err := loadNmapConfig(); err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestValidate(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	tests := []struct {
		name    string
		target  any
		cfg     string
		wantErr string
	}{
		{name: "hostname", target: "example.com"},
		{name: "ipv4", target: "203.0.113.10"},
		{name: "ipv6 literal", target: "[2001:db8::1]"},
		{name: "url host is accepted", target: "https://example.com/a"},
		{name: "url host with port is stripped", target: "http://example.com:8080/x"},
		{name: "target with port is stripped", target: "example.com:443"},
		{name: "missing target", target: nil, wantErr: "target required"},
		{name: "blank target", target: "   ", wantErr: "target required"},
		{name: "cidr range rejected", target: "10.0.0.0/24", wantErr: "invalid target"},
		{name: "port range syntax rejected", target: "example.com:80-90", wantErr: "invalid target"},
		{name: "list rejected", target: "a.com,b.com", wantErr: "invalid target"},
		{name: "wildcard rejected", target: "*.example.com", wantErr: "invalid target"},
		{name: "unbracketed ipv6 rejected", target: "2001:db8::1", wantErr: "invalid target"},
		{name: "bogus port spec", target: "example.com", cfg: `{"ports":"80 --script vuln"}`, wantErr: "invalid ports"},
		{name: "negative count", target: "example.com", cfg: `{"topPorts":-5}`, wantErr: "invalid nmap config"},
		{name: "bad json", target: "example.com", cfg: `{not json`, wantErr: "invalid OASM_CONFIG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OASM_CONFIG", tt.cfg)
			err := NmapAdapter{}.Validate(context.Background(), map[string]any{"target": tt.target})
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// C7 args: deterministic argv vectors. -Pn/-n/-oX - are always present and in a
// fixed order; the target is always last.
func TestBuildNmapArgs_FullAndDefaults(t *testing.T) {
	full := &nmapConfig{Ports: "22,80,443", TopPorts: 100, HostTimeout: 300, Retries: 2}
	wantFull := []string{"-Pn", "-n", "-oX", "-", "-p", "22,80,443", "--host-timeout", "300s", "--max-retries", "2", "10.0.0.1"}
	if got := buildNmapArgs("10.0.0.1", full); !slices.Equal(got, wantFull) {
		t.Errorf("full cfg argv:\n got %v\nwant %v", got, wantFull)
	}

	// Zero config: no -p and no --top-ports, so nmap keeps its own default list.
	wantZero := []string{"-Pn", "-n", "-oX", "-", "10.0.0.1"}
	if got := buildNmapArgs("10.0.0.1", &nmapConfig{}); !slices.Equal(got, wantZero) {
		t.Errorf("zero cfg argv:\n got %v\nwant %v", got, wantZero)
	}

	// topPorts applies only when ports is empty.
	topOnly := []string{"-Pn", "-n", "-oX", "-", "--top-ports", "50", "10.0.0.1"}
	if got := buildNmapArgs("10.0.0.1", &nmapConfig{TopPorts: 50}); !slices.Equal(got, topOnly) {
		t.Errorf("topPorts argv:\n got %v\nwant %v", got, topOnly)
	}
}

// S12 args: the argv actually handed to the nmap binary (captured by the fake)
// matches buildNmapArgs, proving Execute wires OASM_CONFIG -> CLI. The target is
// the resolved address, never the hostname.
func TestExecute_PassesBuiltArgsToBinary(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.json")
	t.Setenv("NMAP_BIN", ensureFakeNmap(t))
	t.Setenv("FAKE_MODE", "default")
	t.Setenv("FAKE_ARGS_FILE", argsFile)
	t.Setenv("OASM_CONFIG", `{"ports":"22,443","hostTimeout":120,"retries":3}`)

	out := make(chan connector.Finding, 64)
	if err := (NmapAdapter{}).Execute(context.Background(), map[string]any{"target": "localhost"}, out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	close(out)
	for range out {
	}

	raw, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read captured args: %v", err)
	}
	var got []string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal captured args: %v", err)
	}
	want := []string{"-Pn", "-n", "-oX", "-", "-p", "22,443", "--host-timeout", "120s", "--max-retries", "3", "127.0.0.1"}
	if !slices.Equal(got, want) {
		t.Errorf("captured argv:\n got %v\nwant %v", got, want)
	}
}

func TestTargetFrom(t *testing.T) {
	cases := []struct{ in, want, wantErr string }{
		{in: "example.com", want: "example.com"},
		{in: " 203.0.113.10 ", want: "203.0.113.10"},
		{in: "[2001:db8::1]", want: "[2001:db8::1]"},
		{in: "https://example.com/a/b?x=1", want: "example.com"},
		{in: "http://user:pw@example.com:8080/x", want: "example.com"},
		{in: "example.com:80", want: "example.com"},
		{in: "10.0.0.0/24", wantErr: "invalid target"},
		{in: "https://10.0.0.0/24", wantErr: "invalid target"},
		{in: "", wantErr: "target required"},
	}
	for _, c := range cases {
		got, err := targetFrom(map[string]any{"target": c.in})
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("targetFrom(%q) error = %v, want %q", c.in, err, c.wantErr)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("targetFrom(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// S2 happy: one Finding per OPEN port only — the filtered port is dropped.
func TestExecute_StreamsOpenPortFindings(t *testing.T) {
	findings, err := collect(t, "default", "localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 open-port findings, got %d: %+v", len(findings), findings)
	}
	want := []struct {
		name      string
		matchedAt string
		port      string
	}{
		{"open tcp/80 (http)", "localhost:80", "tcp/80"},
		{"open tcp/443 (https)", "localhost:443", "tcp/443"},
		{"open udp/53 (domain)", "localhost:53", "udp/53"},
	}
	for i, f := range findings {
		if f.Name != want[i].name || f.MatchedAt != want[i].matchedAt {
			t.Errorf("finding %d: Name=%q MatchedAt=%q, want %q / %q", i, f.Name, f.MatchedAt, want[i].name, want[i].matchedAt)
		}
		if f.Severity != "info" {
			t.Errorf("finding %d: Severity=%q, want info", i, f.Severity)
		}
		if f.Host != "localhost" || f.IP != "127.0.0.1" {
			t.Errorf("finding %d: Host=%q IP=%q, want localhost / 127.0.0.1", i, f.Host, f.IP)
		}
		if len(f.Ports) != 1 || f.Ports[0] != want[i].port {
			t.Errorf("finding %d: Ports=%v, want [%s]", i, f.Ports, want[i].port)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d invalid: %v", i, err)
		}
	}
	// Service/product/version land in Tags so the port view can group without
	// re-parsing descriptions.
	if !slices.Contains(findings[0].Tags, "http") || !slices.Contains(findings[0].Tags, "nginx") ||
		!slices.Contains(findings[0].Tags, "1.27.0") || !slices.Contains(findings[0].Tags, "tcp") {
		t.Errorf("finding 0 tags missing service metadata: %v", findings[0].Tags)
	}
}

// S3 edge: a completed scan with zero open ports is a clean success, not an error.
func TestExecute_NoOpenPortsIsSuccess(t *testing.T) {
	findings, err := collect(t, "empty", "localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// S4 edge: nonzero exit with no output is an error carrying the stderr tail.
func TestExecute_NonZeroExitIsError(t *testing.T) {
	findings, err := collect(t, "fail", "localhost")
	if err == nil {
		t.Fatal("expected error on nonzero exit")
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
	if !strings.Contains(err.Error(), "unrecognized option") {
		t.Errorf("error should carry the stderr tail, got: %v", err)
	}
}

// S5 edge: an unparseable XML document is reported, never silently truncated
// into zero findings.
func TestExecute_TruncatedXMLIsError(t *testing.T) {
	_, err := collect(t, "partial", "localhost")
	if err == nil {
		t.Fatal("expected error on truncated XML")
	}
	if !strings.Contains(err.Error(), "reading output") {
		t.Errorf("error should name the read failure, got: %v", err)
	}
}

// S6 edge: an unresolvable target is fatal before any process is started.
func TestExecute_UnresolvableTargetIsFatal(t *testing.T) {
	t.Setenv("NMAP_BIN", ensureFakeNmap(t))
	t.Setenv("FAKE_MODE", "default")
	err := NmapAdapter{}.Execute(context.Background(),
		map[string]any{"target": "nonexistent.invalid"}, make(chan connector.Finding, 1))
	if err == nil || !strings.Contains(err.Error(), "fatal:") {
		t.Fatalf("want a fatal resolution error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "cannot resolve") {
		t.Errorf("error should name resolution, got: %v", err)
	}
}

// S7 edge: a cancelled context propagates instead of hanging on the tool.
func TestExecute_CancelledContext(t *testing.T) {
	t.Setenv("NMAP_BIN", ensureFakeNmap(t))
	t.Setenv("FAKE_MODE", "hang")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := NmapAdapter{}.Execute(ctx, map[string]any{"target": "localhost"}, make(chan connector.Finding, 1))
	if err == nil {
		t.Fatal("expected an error for a cancelled execution")
	}
}

func TestValidPortSpec(t *testing.T) {
	for _, ok := range []string{"80", "22,80,443", "1-1024", "1-100,443"} {
		if !validPortSpec(ok) {
			t.Errorf("%q should be a valid port spec", ok)
		}
	}
	for _, bad := range []string{"", "80 90", "-p 80", "80;rm -rf /", "top-ports"} {
		if validPortSpec(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
