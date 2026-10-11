package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// arjunHardTimeout bounds the whole Arjun process. Arjun exposes no global
// wall-clock budget (only per-request -T), so this is the real safety net. The
// manifest's resourceDefaults.timeoutSeconds (1800s) sits above it so the
// adapter reports a clean "timed out after 20m0s" error before the container is
// killed.
const arjunHardTimeout = 20 * time.Minute

// defaultMaxUrls caps emitted findings when the config key is unset or invalid.
const defaultMaxUrls = 10000

// arjunSkipMarkers are the stdout/stderr strings Arjun prints when it refuses a
// target outright. Any of them with zero findings means the job never really
// ran against the target — a fatal, non-retryable "target skipped" error.
//
// Deliberately absent: "Webpage is returning different content on each
// request. Skipping." — that is Arjun's own clean-empty result (it returns []
// and exits 0), so it must NOT become a fatal error.
var arjunSkipMarkers = []string{
	"due to errors",
	"doesn't seem to be a webpage",
	"is not a valid URL",
}

// ArjunAdapter runs Arjun (github.com/s0md3v/Arjun) and streams one
// connector.Finding per discovered query parameter
// (Name=MatchedAt=URL?param=, Severity=info, Host=domain).
//
// Arjun is file-based: it writes its JSON result to -oJ and prints only status
// markers to stdout/stderr (stdout is deliberately captured — the skip markers
// land there). Zero parameters found means NO file is written at all, so a
// missing output file is a clean, zero-findings success, not an error.
//
// ponytail: one Finding per parameter keeps the SDK contract (Finding-only
// output); ceiling: one gRPC Result message per finding; upgrade path = raw-data
// channel in the SDK. The worker aggregates Finding.Name into
// jobs_registry.DiscoveredUrl for category url_discovery.
type ArjunAdapter struct{}

// Validate is a no-op; upstream validates inputs.
func (a ArjunAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

// Execute runs Arjun and streams one Finding per unique discovered parameter.
//
// Exit policy, in order:
//  1. Parent ctx cancelled  -> ctx.Err().
//  2. Hard timeout elapsed  -> "arjun: timed out after …" (incomplete run).
//  3. Output file read/parse failure (other than "missing") -> "arjun: read
//     output: …". A missing file is not an error (Arjun writes no file on zero
//     params).
//  4. Zero findings AND a skip marker in the combined tail -> fatal
//     "arjun: target skipped: …".
//  5. Nonzero exit AND zero findings -> "arjun: <waiterr>: <tail>".
//  6. Otherwise nil (bare zero-findings with no marker is a clean success, as
//     is a nonzero exit that still produced partial findings).
func (a ArjunAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	raw, _ := inputs["target"].(string)
	base, host, err := normalizeBaseURL(raw)
	if err != nil {
		return err
	}

	bin := os.Getenv("ARJUN_BIN")
	if bin == "" {
		bin = "arjun"
	}

	cfg, err := loadArjunConfig()
	if err != nil {
		return err
	}

	// ponytail: adapter-side cap is the only real volume bound; ceiling ~ tens
	// of thousands of params per job; upgrade path = raw-data channel in SDK.
	maxUrls := cfg.MaxUrls
	if maxUrls <= 0 {
		maxUrls = defaultMaxUrls
	}

	runCtx, cancel := context.WithTimeout(ctx, arjunHardTimeout)
	defer cancel()

	tmp, err := os.MkdirTemp("", "arjun-*")
	if err != nil {
		return fmt.Errorf("arjun: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	outFile := filepath.Join(tmp, "out.json")

	// Two separate limited writers: limitedWriter is not goroutine-safe, and
	// Arjun splits its markers across stdout and stderr. Never pass -q — the
	// skip markers are printed to stdout and -q would silence them.
	var outTail, errTail limitedWriter
	outTail.buf = new([]byte)
	outTail.limit = 2048
	errTail.buf = new([]byte)
	errTail.limit = 2048

	cmd := exec.CommandContext(runCtx, bin, buildArjunArgs(base, outFile, cfg)...)
	cmd.Stdout = &outTail
	cmd.Stderr = &errTail

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("arjun: start: %w", err)
	}
	waitErr := cmd.Wait()
	tailStr := strings.TrimSpace(string(*outTail.buf) + "\n" + string(*errTail.buf))

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("arjun: timed out after %s", arjunHardTimeout)
	}

	emitted := 0
	data, readErr := os.ReadFile(outFile)
	if readErr != nil {
		// Arjun writes no file when it finds zero params; that is a clean run.
		if !os.IsNotExist(readErr) {
			return fmt.Errorf("arjun: read output: %w", readErr)
		}
	} else {
		var parsed map[string]struct {
			Params  []string          `json:"params"`
			Method  string            `json:"method"`
			Headers map[string]string `json:"headers"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			return fmt.Errorf("arjun: read output: %w", err)
		}
		seen := make(map[string]bool)
	parse:
		for u, entry := range parsed {
			// skip non-http(s) keys Arjun may echo back.
			if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
				continue
			}
			for _, param := range entry.Params {
				name := paramName(u, param)
				if seen[name] {
					continue
				}
				seen[name] = true
				if emitted >= maxUrls {
					break parse
				}
				f := connector.Finding{
					Name:      name,
					Severity:  "info",
					MatchedAt: name,
					Host:      host,
					Timestamp: time.Now(),
				}
				select {
				case <-ctx.Done():
					return ctx.Err()
				case out <- f:
					emitted++
				}
			}
		}
	}

	if emitted == 0 && isSkipMarker(tailStr) {
		return fmt.Errorf("arjun: target skipped: %s", tailStr)
	}
	if waitErr != nil && emitted == 0 {
		if tailStr != "" {
			return fmt.Errorf("arjun: %w: %s", waitErr, tailStr)
		}
		return fmt.Errorf("arjun: %w", waitErr)
	}
	return nil
}

// normalizeBaseURL validates the target and returns the base URL handed to
// Arjun's -u plus the bare host recorded on findings. A target without an
// http(s) scheme is assumed https ("example.com" -> "https://example.com").
func normalizeBaseURL(raw string) (base, host string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("arjun: target required")
	}
	// A target starting with "-" would be swallowed as an Arjun flag.
	if strings.HasPrefix(s, "-") {
		return "", "", fmt.Errorf("arjun: invalid target %q", raw)
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", "", fmt.Errorf("arjun: invalid target %q: %w", raw, err)
	}
	// Bare host, "host:port", or a path all parse with an empty Host; assume
	// https and re-parse. A real scheme+host target is left untouched.
	if u.Host == "" {
		u, err = url.Parse("https://" + s)
		if err != nil || u.Hostname() == "" {
			return "", "", fmt.Errorf("arjun: invalid target %q", raw)
		}
	}
	return u.String(), u.Hostname(), nil
}

// paramName renders the finding name for a parameter discovered on u: the URL
// with the parameter appended as a query key (no value), joined with "?" or
// "&" depending on whether u already carries a query.
func paramName(u, param string) string {
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	return u + sep + param + "="
}

// isSkipMarker reports whether the combined stdout/stderr tail carries an Arjun
// "target refused" marker.
func isSkipMarker(tail string) bool {
	for _, m := range arjunSkipMarkers {
		if strings.Contains(tail, m) {
			return true
		}
	}
	return false
}

// limitedWriter buffers stdout/stderr, keeping at most `limit` bytes.
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
