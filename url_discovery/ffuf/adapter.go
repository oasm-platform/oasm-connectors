package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// ffufHardTimeout bounds the whole ffuf process. ffuf's -timeout is a
// PER-REQUEST timeout only; -maxtime is a soft deadline ffuf may overshoot; this
// is the real safety net. The manifest's resourceDefaults.timeoutSeconds (1800s)
// sits above it so the adapter reports a clean timeout before the container is
// killed.
const ffufHardTimeout = 20 * time.Minute

// defaultMaxUrls caps emitted findings when the config key is unset or invalid.
const defaultMaxUrls = 10000

// FfufAdapter runs ffuf (github.com/ffuf/ffuf) with -json and streams each match
// as one connector.Finding (Name=URL, Severity=info, MatchedAt=URL, Host=target
// host).
//
// ponytail: one Finding per match keeps the SDK contract (Finding-only output);
// ceiling: the SDK sends one gRPC Result message per finding (sdk/runtime);
// upgrade path = an optional raw-data channel in the SDK. The worker aggregates
// Finding.Name into jobs_registry.DiscoveredUrl for category url_discovery.
type FfufAdapter struct{}

// Validate is a no-op; upstream validates inputs.
func (a FfufAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

// Execute runs ffuf and streams one Finding per unique discovered URL.
//
// ffuf emits one JSON object per line (-json) whose `input` field is base64 and
// whose `url` field is the matched URL. Exit-code semantics mirror gau/katana: a
// nonzero exit alone is not fatal — fatal only when the process fails AND
// produced no output (the error carries the stderr tail). A nonzero exit WITH
// partial output is success. A hard timeout is always an error. Hitting the
// maxUrls cap kills ffuf, keeps the partial findings and returns success.
func (a FfufAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	raw, _ := inputs["target"].(string)
	base, host, err := normalizeBaseURL(raw)
	if err != nil {
		return err
	}

	bin := os.Getenv("FFUF_BIN")
	if bin == "" {
		bin = "ffuf"
	}

	cfg, err := loadFfufConfig()
	if err != nil {
		return err
	}

	wordlist := resolveFfufWordlist(cfg)
	maxUrls := cfg.MaxUrls
	if maxUrls <= 0 {
		maxUrls = defaultMaxUrls
	}

	runCtx, cancel := context.WithTimeout(ctx, ffufHardTimeout)
	defer cancel()

	var tail limitedWriter
	tail.buf = new([]byte)
	tail.limit = 2048

	cmd := exec.CommandContext(runCtx, bin, buildFfufArgs(base, wordlist, cfg)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("ffuf: stdout pipe: %w", err)
	}
	cmd.Stderr = &tail

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("ffuf: start: %w", err)
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
		// ffuf -json emits one object per line; `input` is base64 and is never
		// parsed here — the `url` field carries the matched URL.
		var rec struct {
			URL    string `json:"url"`
			Host   string `json:"host"`
			Status int64  `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			continue
		}
		u := strings.TrimSpace(rec.URL)
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		if seen[u] {
			continue
		}
		seen[u] = true
		if emitted >= maxUrls {
			_ = cmd.Process.Kill()
			break
		}
		f := connector.Finding{
			Name:      u,
			Severity:  "info",
			MatchedAt: u,
			Host:      host,
			Timestamp: time.Now(),
		}
		select {
		case <-ctx.Done():
			_ = cmd.Wait()
			return ctx.Err()
		case <-runCtx.Done():
			// Hard timeout: kill ffuf and report the timeout instead of
			// blocking on a send nobody will read.
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return fmt.Errorf("ffuf: timed out after %s", ffufHardTimeout)
		case out <- f:
			emitted++
		}
	}
	scanErr := scanner.Err()
	if scanErr != nil {
		// Nobody is draining stdout any more: without a kill ffuf blocks on
		// the pipe and cmd.Wait would hang until the hard timeout, hiding the
		// real read error.
		_ = cmd.Process.Kill()
	}

	waitErr := cmd.Wait()
	tailStr := strings.TrimSpace(string(*tail.buf))

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("ffuf: timed out after %s", ffufHardTimeout)
	}
	if waitErr != nil && emitted == 0 {
		if tailStr != "" {
			return fmt.Errorf("ffuf: %w: %s", waitErr, tailStr)
		}
		return fmt.Errorf("ffuf: %w", waitErr)
	}
	if scanErr != nil {
		return fmt.Errorf("ffuf: reading output: %w", scanErr)
	}
	return nil
}

// normalizeBaseURL validates and canonicalizes the target into the base URL ffuf
// scans (with "/FUZZ" appended by the argv builder) and the bare target host
// attached to every finding. A missing scheme defaults to https. The path is
// kept (trailing slash trimmed) so a scan can be rooted at a subpath.
func normalizeBaseURL(raw string) (string, string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("target required")
	}
	// ffuf parses flags interspersed and -u is a positional flag: a target
	// starting with "-" would be swallowed as a flag; a comma would be read as
	// a w:FH list separator. Reject both.
	if strings.HasPrefix(s, "-") || strings.Contains(s, ",") {
		return "", "", fmt.Errorf("ffuf: invalid target %q", raw)
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("ffuf: invalid target %q", raw)
	}
	base := u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/")
	return base, u.Hostname(), nil
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
