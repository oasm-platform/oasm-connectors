package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// rustscanHardTimeout bounds the whole rustscan process. The manifest's
// resourceDefaults.timeoutSeconds (1800s) sits above it so the adapter reports a
// clean "timed out after 20m0s" error before the container is killed.
const rustscanHardTimeout = 20 * time.Minute

// greppableLine is rustscan -g's entire contract: one line per host that has at
// least one open port, "host -> [80,443]" (ports ascending, comma-separated).
// A host with no open ports prints no line at all.
var greppableLine = regexp.MustCompile(`^(.+?) -> \[([0-9,]*)\]$`)

// RustscanAdapter runs rustscan (github.com/bee-san/RustScan) in greppable mode
// and streams one connector.Finding per OPEN port (Severity=info,
// Name="open tcp/443", MatchedAt=host:port, Host=target, IP=resolved address).
//
// Greppable mode means no nmap, so findings carry no service/product/version —
// that is nmap's job, and the catalogue runs both connectors side by side.
type RustscanAdapter struct{}

// Validate rejects malformed inputs/cfg before any process or network resource
// is spent. It is pure: no DNS, no socket.
func (a RustscanAdapter) Validate(_ context.Context, inputs map[string]any) error {
	if _, err := targetFrom(inputs); err != nil {
		return err
	}
	cfg, err := loadRustscanConfig()
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}
	return nil
}

// validateConfig is shared by Validate and Execute so a bad profile can never
// reach argv through a path that skipped validation.
func validateConfig(cfg *rustscanConfig) error {
	if cfg.Ports != "" && !validPortList(cfg.Ports) {
		return fmt.Errorf("invalid ports %q (comma-separated port numbers 1-65535; use range for \"1-1024\")", cfg.Ports)
	}
	if cfg.Range != "" && !validPortRange(cfg.Range) {
		return fmt.Errorf("invalid range %q (start-end with start <= end, e.g. 1-1024)", cfg.Range)
	}
	if cfg.TimeoutMs < 0 || cfg.Tries < 0 || cfg.BatchSize < 0 {
		return fmt.Errorf("invalid rustscan config: counts must not be negative")
	}
	if cfg.BatchSize > 65535 {
		return fmt.Errorf("invalid batchSize %d (maximum 65535)", cfg.BatchSize)
	}
	if cfg.TimeoutMs > 60000 {
		return fmt.Errorf("invalid timeoutMs %d (maximum 60000)", cfg.TimeoutMs)
	}
	return nil
}

// targetFrom extracts a single host from the inputs. The scheme/path strip is
// deliberately NOT applied to a slash-bearing non-URL ("10.0.0.0/24"): unrolling
// a CIDR would silently turn a network request into a single-host scan.
func targetFrom(inputs map[string]any) (string, error) {
	raw, _ := inputs["target"].(string)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("target required")
	}
	if host := normalizeTarget(trimmed); host != "" {
		return host, nil
	}
	return "", fmt.Errorf("invalid target %q (single host only, no CIDR/range/list)", raw)
}

// Execute runs rustscan in greppable mode and streams one Finding per open port.
//
// Exit-code semantics, verified against 2.3.0 and 2.4.1: 0 means the scan
// completed, even when every port was closed (a clean, zero-findings run); 2 is
// clap rejecting our own argv (our bug or a bad profile, never retryable); any
// other nonzero exit is rustscan itself failing and is retryable. rustscan can
// exit 1 with both streams empty, so the error names the target instead of
// shipping an empty tail.
func (a RustscanAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	target, err := targetFrom(inputs)
	if err != nil {
		return err
	}
	cfg, err := loadRustscanConfig()
	if err != nil {
		return err
	}
	if err := validateConfig(cfg); err != nil {
		return err
	}

	bin := os.Getenv("RUSTSCAN_BIN")
	if bin == "" {
		bin = "rustscan"
	}

	// Resolve once so every finding carries the scanned address, and so the
	// binary is handed an address it cannot re-interpret as a list or a CIDR.
	// An unresolvable target is fatal — rustscan would only fail seconds later
	// with an empty stderr and exit 1.
	ip := resolveIPv4(target)
	if ip == "" {
		return fmt.Errorf("fatal: rustscan: cannot resolve %q", target)
	}

	runCtx, cancel := context.WithTimeout(ctx, rustscanHardTimeout)
	defer cancel()

	var stderr limitedWriter
	stderr.buf = new([]byte)
	stderr.limit = 2048

	proto := "tcp"
	if cfg.UDP {
		proto = "udp"
	}

	cmd := exec.CommandContext(runCtx, bin, buildRustscanArgs(ip, cfg)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("rustscan: stdout pipe: %w", err)
	}
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("rustscan: start: %w", err)
	}

	emitted := 0
	var skipped string
	scanErr := scanGreppable(stdout, func(port int) error {
		f := openPortFinding(target, ip, proto, strconv.Itoa(port))
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-runCtx.Done():
			return runCtx.Err()
		case out <- f:
			emitted++
			return nil
		}
	}, &skipped)

	// A cancelled or timed-out run must not wait on the process: kill it, then
	// reap it so no zombie survives into the next warm-pool execution.
	if scanErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if runCtx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("rustscan: timed out after %s", rustscanHardTimeout)
		}
		return fmt.Errorf("retryable: rustscan: reading output: %v", scanErr)
	}

	waitErr := cmd.Wait()
	tail := strings.TrimSpace(string(*stderr.buf))

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("rustscan: timed out after %s", rustscanHardTimeout)
	}
	if waitErr != nil {
		var exitErr *exec.ExitError
		code := -1
		if errors.As(waitErr, &exitErr) {
			code = exitErr.ExitCode()
		}
		msg := fmt.Sprintf("rustscan: exited %d scanning %s", code, target)
		if tail != "" {
			msg += ": " + tail
		}
		if code == 2 {
			// clap rejected the argv we built — a configuration bug, not a
			// transient tool failure.
			return fmt.Errorf("fatal: %s", msg)
		}
		return fmt.Errorf("retryable: %s", msg)
	}
	if skipped != "" {
		// Exit 0 but a line we could not read: report it rather than letting
		// unparseable output look like a host with no open ports.
		return fmt.Errorf("retryable: rustscan: unreadable output line %q", skipped)
	}
	return nil
}

// scanGreppable reads rustscan -g's stdout line by line and calls emit for every
// open port as it arrives, so findings stream instead of buffering a whole scan.
// The first line that is neither blank nor a greppable record is kept in
// skipped: the caller turns that into an error, never into silence.
func scanGreppable(r io.Reader, emit func(port int) error, skipped *string) error {
	sc := bufio.NewScanner(r)
	// A full 65535-port record is ~400KB on one line; the default 64KB token
	// limit would fail the scan it is supposed to parse.
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		m := greppableLine.FindStringSubmatch(line)
		if m == nil {
			if *skipped == "" {
				*skipped = line
			}
			continue
		}
		if m[2] == "" {
			continue
		}
		for _, p := range strings.Split(m[2], ",") {
			n, err := strconv.Atoi(p)
			if err != nil || !portInRange(n) {
				if *skipped == "" {
					*skipped = line
				}
				continue
			}
			if err := emit(n); err != nil {
				return err
			}
		}
	}
	return sc.Err()
}

// openPortFinding maps one open port onto the connector contract. Name stays
// stable and greppable ("open tcp/443") so the dashboard's port view can group
// by protocol without re-parsing descriptions — exactly what the nmap connector
// emits when it has no service name to append.
func openPortFinding(target, ip, proto, portID string) connector.Finding {
	endpoint := portString(proto, portID)
	return connector.Finding{
		Name:      "open " + endpoint,
		Severity:  "info",
		MatchedAt: target + ":" + portID,
		Host:      target,
		IP:        ip,
		Ports:     []string{endpoint},
		Tags:      []string{"port", proto},
		Timestamp: time.Now(),
	}
}

// portString renders "tcp/443" from the protocol and port.
func portString(proto, portID string) string { return proto + "/" + portID }

// resolveIPv4 returns the first IPv4 address of host, or host verbatim when it
// already is an IP literal, or "" when it cannot be resolved.
func resolveIPv4(host string) string {
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if net.ParseIP(h) != nil {
		return h
	}
	addrs, err := net.LookupHost(h)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if net.ParseIP(a) != nil && strings.Contains(a, ".") {
			return a
		}
	}
	return ""
}

// limitedWriter buffers stderr, keeping at most `limit` bytes.
type limitedWriter struct {
	buf   *[]byte
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	if len(*w.buf) > w.limit {
		*w.buf = (*w.buf)[len(*w.buf)-w.limit:]
	}
	return len(p), nil
}
