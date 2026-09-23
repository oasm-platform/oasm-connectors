package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

var (
	fakeRustscanPath string
	fakeRustscanOnce sync.Once
)

// ensureFakeRustscan builds the fake rustscan binary once for the test run. Uses
// os.MkdirTemp (not t.TempDir) so the binary survives across tests.
func ensureFakeRustscan(t *testing.T) string {
	t.Helper()
	fakeRustscanOnce.Do(func() {
		dir, err := os.MkdirTemp("", "fake-rustscan-*")
		if err != nil {
			t.Fatalf("create temp dir: %v", err)
		}
		ext := ""
		if runtime.GOOS == "windows" {
			ext = ".exe"
		}
		fakeRustscanPath = filepath.Join(dir, "fake-rustscan"+ext)
		cmd := exec.Command("go", "build", "-o", fakeRustscanPath, "./testdata/fake-rustscan")
		cmd.Dir = "."
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("build fake-rustscan: %v\n%s", err, out)
		}
	})
	return fakeRustscanPath
}

// collect runs Execute against the fake rustscan with FAKE_MODE=mode and returns
// the emitted findings plus the returned error.
func collect(t *testing.T, mode, target string) ([]connector.Finding, error) {
	t.Helper()
	t.Setenv("RUSTSCAN_BIN", ensureFakeRustscan(t))
	t.Setenv("FAKE_MODE", mode)

	out := make(chan connector.Finding, 64)
	err := RustscanAdapter{}.Execute(context.Background(), map[string]any{"target": target}, out)
	close(out)

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

func TestLoadRustscanConfig_UnsetIsZeroConfig(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadRustscanConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if *cfg != (rustscanConfig{}) {
		t.Fatalf("expected zero config, got %+v", cfg)
	}
}

func TestLoadRustscanConfig_ParsesAndRejects(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"ports":"22,80","range":"1-1024","timeoutMs":2000,"tries":2,"batchSize":1000,"udp":true}`)
	cfg, err := loadRustscanConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := rustscanConfig{Ports: "22,80", Range: "1-1024", TimeoutMs: 2000, Tries: 2, BatchSize: 1000, UDP: true}
	if *cfg != want {
		t.Fatalf("config not parsed: got %+v want %+v", cfg, want)
	}

	t.Setenv("OASM_CONFIG", "{not json")
	if _, err := loadRustscanConfig(); err == nil {
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
		{name: "host list rejected", target: "a.com,b.com", wantErr: "invalid target"},
		{name: "wildcard rejected", target: "*.example.com", wantErr: "invalid target"},
		{name: "unbracketed ipv6 rejected", target: "2001:db8::1", wantErr: "invalid target"},
		{name: "port range syntax rejected", target: "example.com:80-90", wantErr: "invalid target"},
		{name: "port list", target: "example.com", cfg: `{"ports":"80,443,8080"}`},
		{name: "port range", target: "example.com", cfg: `{"range":"1-1024"}`},
		{name: "port range in ports field rejected", target: "example.com", cfg: `{"ports":"1-1024"}`, wantErr: "invalid ports"},
		{name: "port zero rejected", target: "example.com", cfg: `{"ports":"0"}`, wantErr: "invalid ports"},
		{name: "port above 65535 rejected", target: "example.com", cfg: `{"ports":"65536"}`, wantErr: "invalid ports"},
		{name: "flag in ports rejected", target: "example.com", cfg: `{"ports":"80 -sV"}`, wantErr: "invalid ports"},
		{name: "reversed range rejected", target: "example.com", cfg: `{"range":"1000-1"}`, wantErr: "invalid range"},
		{name: "open range rejected", target: "example.com", cfg: `{"range":"1-"}`, wantErr: "invalid range"},
		{name: "negative count", target: "example.com", cfg: `{"batchSize":-5}`, wantErr: "must not be negative"},
		{name: "batch size above maximum", target: "example.com", cfg: `{"batchSize":70000}`, wantErr: "invalid batchSize"},
		{name: "timeout above maximum", target: "example.com", cfg: `{"timeoutMs":600000}`, wantErr: "invalid timeoutMs"},
		{name: "bad json", target: "example.com", cfg: `{not json`, wantErr: "invalid OASM_CONFIG"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OASM_CONFIG", tt.cfg)
			err := RustscanAdapter{}.Validate(context.Background(), map[string]any{"target": tt.target})
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

// -g/-n are always present and in a fixed order; the target is always last, so a
// captured argv is comparable verbatim.
func TestBuildRustscanArgs(t *testing.T) {
	full := &rustscanConfig{Ports: "22,80,443", Range: "1-1024", TimeoutMs: 2000, Tries: 3, BatchSize: 2000, UDP: true}
	// ports wins over range, exactly like the nmap connector's ports/topPorts.
	wantFull := []string{"-g", "-n", "--udp", "-p", "22,80,443", "-b", "2000", "-t", "2000", "--tries", "3", "-a", "10.0.0.1"}
	if got := buildRustscanArgs("10.0.0.1", full); !slices.Equal(got, wantFull) {
		t.Errorf("full cfg argv:\n got %v\nwant %v", got, wantFull)
	}

	// Zero config emits no port flag at all, so rustscan keeps its own default.
	wantZero := []string{"-g", "-n", "-a", "10.0.0.1"}
	if got := buildRustscanArgs("10.0.0.1", &rustscanConfig{}); !slices.Equal(got, wantZero) {
		t.Errorf("zero cfg argv:\n got %v\nwant %v", got, wantZero)
	}

	wantRange := []string{"-g", "-n", "-r", "1-1024", "-a", "10.0.0.1"}
	if got := buildRustscanArgs("10.0.0.1", &rustscanConfig{Range: "1-1024"}); !slices.Equal(got, wantRange) {
		t.Errorf("range argv:\n got %v\nwant %v", got, wantRange)
	}
}

// The argv actually handed to the binary (captured by the fake) matches
// buildRustscanArgs, proving Execute wires OASM_CONFIG -> CLI, and the address is
// the resolved one.
func TestExecute_PassesBuiltArgsToBinary(t *testing.T) {
	argsFile := filepath.Join(t.TempDir(), "args.json")
	t.Setenv("RUSTSCAN_BIN", ensureFakeRustscan(t))
	t.Setenv("FAKE_MODE", "default")
	t.Setenv("FAKE_ARGS_FILE", argsFile)
	t.Setenv("OASM_CONFIG", `{"range":"1-1024","timeoutMs":2000,"tries":2}`)

	out := make(chan connector.Finding, 64)
	if err := (RustscanAdapter{}).Execute(context.Background(), map[string]any{"target": "localhost"}, out); err != nil {
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
	want := []string{"-g", "-n", "-r", "1-1024", "-t", "2000", "--tries", "2", "-a", "127.0.0.1"}
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

// S2 happy: one Finding per open port, host from the input, IP from resolution.
func TestExecute_StreamsOpenPortFindings(t *testing.T) {
	findings, err := collect(t, "default", "localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 open-port findings, got %d: %+v", len(findings), findings)
	}
	for i, want := range []struct{ name, matchedAt, endpoint string }{
		{"open tcp/80", "localhost:80", "tcp/80"},
		{"open tcp/443", "localhost:443", "tcp/443"},
	} {
		f := findings[i]
		if f.Name != want.name || f.MatchedAt != want.matchedAt {
			t.Errorf("finding %d: Name=%q MatchedAt=%q, want %q / %q", i, f.Name, f.MatchedAt, want.name, want.matchedAt)
		}
		if f.Severity != "info" {
			t.Errorf("finding %d: Severity=%q, want info", i, f.Severity)
		}
		if f.Host != "localhost" || f.IP != "127.0.0.1" {
			t.Errorf("finding %d: Host=%q IP=%q, want localhost / 127.0.0.1", i, f.Host, f.IP)
		}
		if len(f.Ports) != 1 || f.Ports[0] != want.endpoint {
			t.Errorf("finding %d: Ports=%v, want [%s]", i, f.Ports, want.endpoint)
		}
		if !slices.Contains(f.Tags, "port") || !slices.Contains(f.Tags, "tcp") {
			t.Errorf("finding %d: tags missing port/tcp: %v", i, f.Tags)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d invalid: %v", i, err)
		}
	}
}

// udp=true relabels the same ports: greppable output carries no protocol.
func TestExecute_UDPFindingProtocol(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"udp":true}`)
	findings, err := collect(t, "default", "localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 2 || findings[0].Ports[0] != "udp/80" || findings[0].Name != "open udp/80" {
		t.Fatalf("want udp findings, got %+v", findings)
	}
}

// S3 edge: a completed scan with no open ports is a clean success, not an error.
func TestExecute_NoOpenPortsIsSuccess(t *testing.T) {
	findings, err := collect(t, "empty", "localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// S4 edge: exit 0 with output we cannot read is reported, never silently
// downgraded to "no open ports".
func TestExecute_UnreadableOutputIsError(t *testing.T) {
	findings, err := collect(t, "garbage", "localhost")
	if err == nil {
		t.Fatal("expected error on unreadable output")
	}
	if !strings.Contains(err.Error(), "unreadable output line") {
		t.Errorf("error should name the unreadable line, got: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

// S5 edge: clap rejecting our argv (exit 2) is a configuration bug, not a
// transient failure — the Worker must not retry it.
func TestExecute_BadArgsIsFatal(t *testing.T) {
	_, err := collect(t, "badargs", "localhost")
	if err == nil || !strings.Contains(err.Error(), "fatal:") {
		t.Fatalf("want a fatal error for exit 2, got: %v", err)
	}
	if !strings.Contains(err.Error(), "exited 2") {
		t.Errorf("error should carry the exit code, got: %v", err)
	}
}

// S6 edge: a nonzero exit from rustscan itself is retryable and carries the
// stderr tail.
func TestExecute_ScanFailureIsRetryable(t *testing.T) {
	_, err := collect(t, "fail", "localhost")
	if err == nil || !strings.Contains(err.Error(), "retryable:") {
		t.Fatalf("want a retryable error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "failed to open sockets") {
		t.Errorf("error should carry the stderr tail, got: %v", err)
	}
}

// S7 edge: an unresolvable target is fatal before any process is started.
func TestExecute_UnresolvableTargetIsFatal(t *testing.T) {
	t.Setenv("RUSTSCAN_BIN", ensureFakeRustscan(t))
	t.Setenv("FAKE_MODE", "default")
	err := RustscanAdapter{}.Execute(context.Background(),
		map[string]any{"target": "nonexistent.invalid"}, make(chan connector.Finding, 1))
	if err == nil || !strings.Contains(err.Error(), "fatal:") || !strings.Contains(err.Error(), "cannot resolve") {
		t.Fatalf("want a fatal resolution error, got: %v", err)
	}
}

// S8 edge: a cancelled context propagates instead of hanging on the tool.
func TestExecute_CancelledContext(t *testing.T) {
	t.Setenv("RUSTSCAN_BIN", ensureFakeRustscan(t))
	t.Setenv("FAKE_MODE", "hang")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := RustscanAdapter{}.Execute(ctx, map[string]any{"target": "localhost"}, make(chan connector.Finding, 1))
	if err == nil {
		t.Fatal("expected an error for a cancelled execution")
	}
}

func TestValidPortList(t *testing.T) {
	for _, ok := range []string{"80", "22,80,443", "1", "65535"} {
		if !validPortList(ok) {
			t.Errorf("%q should be a valid port list", ok)
		}
	}
	for _, bad := range []string{"", "80 90", "1-1024", "-p 80", "80;rm -rf /", "0", "65536", "80,", ",80"} {
		if validPortList(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestValidPortRange(t *testing.T) {
	for _, ok := range []string{"1-1024", "80-80", "1-65535"} {
		if !validPortRange(ok) {
			t.Errorf("%q should be a valid port range", ok)
		}
	}
	for _, bad := range []string{"", "1024-1", "1-", "-80", "1-2-3", "0-80", "1-65536", "80"} {
		if validPortRange(bad) {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

// A full-range greppable record is one very long line (~400KB); the reader's
// token buffer must not be the reason a legitimate scan fails.
func TestScanGreppable_FullRangeLine(t *testing.T) {
	var line strings.Builder
	line.WriteString("127.0.0.1 -> [")
	for p := 1; p <= 65535; p++ {
		if p > 1 {
			line.WriteByte(',')
		}
		line.WriteString(strconv.Itoa(p))
	}
	line.WriteString("]\n")

	var ports []int
	var skipped string
	if err := scanGreppable(strings.NewReader(line.String()), func(p int) error {
		ports = append(ports, p)
		return nil
	}, &skipped); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if skipped != "" || len(ports) != 65535 || ports[0] != 1 || ports[65534] != 65535 {
		t.Fatalf("parsed %d ports, skipped=%q", len(ports), skipped)
	}
}
