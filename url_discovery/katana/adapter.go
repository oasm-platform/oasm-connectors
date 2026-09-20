package main

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// katanaHardTimeout bounds the whole katana process. katana's -timeout is a
// PER-REQUEST timeout only and -ct (crawl duration) is emitted verbatim and can
// overshoot; this is the real safety net. The manifest's
// resourceDefaults.timeoutSeconds (1200s) sits above it so the adapter reports a
// clean "timed out after 10m0s" error before the container is killed.
const katanaHardTimeout = 10 * time.Minute

// defaultMaxUrls caps emitted findings when the config key is unset or invalid.
const defaultMaxUrls = 10000

// KatanaAdapter runs katana (github.com/projectdiscovery/katana) and streams
// each discovered HTTP/HTTPS URL as one connector.Finding
// (Name=URL, Severity=info, MatchedAt=URL, Host=domain).
//
// ponytail: one Finding per URL keeps the SDK contract (Finding-only output);
// ceiling: the SDK sends one gRPC Result message per finding (sdk/runtime), so
// thousands of URLs = thousands of messages (measured: iana.org -d 2 = 53,520
// unique URLs); upgrade path = add an optional raw-data channel to the SDK. The
// worker aggregates Finding.Name into jobs_registry.DiscoveredUrl for category
// url_discovery.
type KatanaAdapter struct{}

// Validate is a no-op; upstream validates inputs.
func (a KatanaAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

// Execute runs katana and streams one Finding per unique discovered http(s) URL.
//
// Exit-code semantics: katana's exit code is unreliable — an unreachable target
// exits 0, empty input exits 0, and a runner initialization failure prints
// `could not create runner` to stderr and ALSO exits 0; only an unknown flag
// exits nonzero (2). So a nonzero exit alone is not fatal. Fatal only when:
//   - the process fails (nonzero exit) AND produced no output, or
//   - the `could not create runner` marker appears AND no output was produced
//     (the exit code cannot signal this case).
//
// A nonzero exit WITH partial output is treated as success (partial results are
// still useful). A hard timeout is always reported as an error, even with
// partial output, because the run is incomplete. Exit 0 with zero URLs is a
// clean, zero-findings success — an empty crawl, not a failure. Hitting the
// maxUrls cap kills the process, keeps the partial findings and returns success.
func (a KatanaAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	raw, _ := inputs["target"].(string)
	target := normalizeTarget(raw)
	if target == "" {
		return fmt.Errorf("target required")
	}
	// katana's -u is a comma-separated list (string[]): a comma in the target
	// would silently add a second host and crawl outside the registered
	// domain the connector promises to stay in.
	if strings.Contains(target, ",") {
		return fmt.Errorf("katana: invalid target %q", raw)
	}

	bin := os.Getenv("KATANA_BIN")
	if bin == "" {
		bin = "katana"
	}

	cfg, err := loadKatanaConfig()
	if err != nil {
		return err
	}

	// ponytail: adapter-side cap is the only real volume bound (measured: -mdp
	// caps pages, not emitted rows, and 53k+ unique URLs are reachable in under
	// 4 min); ceiling ~ tens of thousands of URLs per job; upgrade path =
	// raw-data channel in the SDK. Truncation keeps partial findings and returns
	// success.
	maxUrls := cfg.MaxUrls
	if maxUrls <= 0 {
		maxUrls = defaultMaxUrls
	}

	runCtx, cancel := context.WithTimeout(ctx, katanaHardTimeout)
	defer cancel()

	var stderr limitedWriter
	stderr.buf = new([]byte)
	stderr.limit = 2048

	cmd := exec.CommandContext(runCtx, bin, buildKatanaArgs(target, cfg)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("katana: stdout pipe: %w", err)
	}
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("katana: start: %w", err)
	}

	emitted := 0
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// katana emits non-http schemes by default (ftp:, mailto:) — keep only
		// URLs the discovered_urls contract can use.
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			continue
		}
		// katana has no global URL dedupe (measured: 5,663 unique from 10,806
		// lines at -d 1), so the adapter dedupes.
		if seen[line] {
			continue
		}
		seen[line] = true
		if emitted >= maxUrls {
			_ = cmd.Process.Kill()
			break
		}
		f := connector.Finding{
			Name:      line,
			Severity:  "info",
			MatchedAt: line,
			Host:      target,
			Timestamp: time.Now(),
		}
		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return ctx.Err()
		case <-runCtx.Done():
			// Hard timeout: kill katana and report the timeout instead of
			// blocking on a send nobody will read.
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("katana: timed out after %s", katanaHardTimeout)
		case out <- f:
			emitted++
		}
	}
	scanErr := scanner.Err()
	if scanErr != nil {
		// Nobody is draining stdout any more: without a kill katana blocks on
		// the pipe and cmd.Wait would hang until the hard timeout, hiding the
		// real read error.
		_ = cmd.Process.Kill()
	}

	waitErr := cmd.Wait()
	tail := strings.TrimSpace(string(*stderr.buf))

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("katana: timed out after %s", katanaHardTimeout)
	}
	if waitErr != nil && emitted == 0 {
		if tail != "" {
			return fmt.Errorf("katana: %w: %s", waitErr, tail)
		}
		return fmt.Errorf("katana: %w", waitErr)
	}
	// katana exits 0 on runner init failure; the stderr marker is the only signal.
	if emitted == 0 && strings.Contains(tail, katanaRunnerInitMarker) {
		return fmt.Errorf("katana: runner init failed: %s", tail)
	}
	if scanErr != nil {
		return fmt.Errorf("katana: reading output: %w", scanErr)
	}
	return nil
}

// normalizeTarget strips scheme/path/query/port, leaving the bare host katana
// expects as its -u target: "https://example.com/a/b?x=1" -> "example.com".
func normalizeTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// net/url resolves userinfo and IPv6 literals correctly
	// ("http://user:pw@example.com/x" -> example.com, "[::1]:8080" -> ::1);
	// a bare "host:port" is not a URL, so it falls through to the manual strip.
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 {
			return s[1:i]
		}
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
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
