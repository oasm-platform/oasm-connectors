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

// dirsearchHardTimeout bounds the whole dirsearch process. dirsearch's
// --max-time is a per-run budget that can be omitted; this is the real safety
// net. The manifest's resourceDefaults.timeoutSeconds (1800s) sits above it so
// the adapter reports a clean "timed out after 20m0s" error before the
// container is killed.
const dirsearchHardTimeout = 20 * time.Minute

// defaultMaxUrls caps emitted findings when the config key is unset or invalid.
const defaultMaxUrls = 10000

// DirsearchAdapter runs dirsearch (github.com/maurosoria/dirsearch) and streams
// each discovered HTTP/HTTPS URL from its JSON report as one connector.Finding
// (Name=URL, Severity=info, MatchedAt=URL, Host=domain).
//
// ponytail: one Finding per URL keeps the SDK contract (Finding-only output);
// ceiling: the SDK sends one gRPC Result message per finding (sdk/runtime), so
// thousands of URLs = thousands of messages; upgrade path = add an optional
// raw-data channel to the SDK. The worker aggregates Finding.Name into
// jobs_registry.DiscoveredUrl for category url_discovery.
type DirsearchAdapter struct{}

// Validate is a no-op; upstream validates inputs.
func (a DirsearchAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

// Execute runs dirsearch and streams one Finding per unique discovered http(s)
// URL parsed from the JSON report dirsearch writes to -o.
//
// Exit-code semantics: dirsearch exits 0 even for an unreachable target or zero
// results, so a nonzero exit is not the only failure signal. The report file is
// the source of truth: dirsearch creates it on every completed run, so a
// missing report is ALWAYS an error (wrong -o path or a target that never ran)
// regardless of the exit code. Findings arrive after the process exits
// (file-based), so the whole result set is buffered and the maxUrls cap is
// applied at parse time. A nonzero exit with partial report data is success
// (partial results are useful). A hard timeout is always an error, even with a
// partial report, because the run is incomplete. An empty `results` array is a
// clean, zero-findings success.
func (a DirsearchAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	raw, _ := inputs["target"].(string)
	base, host, err := normalizeBaseURL(raw)
	if err != nil {
		return err
	}

	bin := os.Getenv("DIRSEARCH_BIN")
	if bin == "" {
		bin = "dirsearch"
	}

	cfg, err := loadDirsearchConfig()
	if err != nil {
		return err
	}
	wordlist := resolveDirsearchWordlist(cfg)
	maxUrls := cfg.MaxUrls
	if maxUrls <= 0 {
		maxUrls = defaultMaxUrls
	}

	runCtx, cancel := context.WithTimeout(ctx, dirsearchHardTimeout)
	defer cancel()

	// A fresh output path per run: dirsearch appends to an existing report file,
	// so reusing a path would merge results across warm-pool executions.
	tmp, err := os.MkdirTemp("", "dirsearch-*")
	if err != nil {
		return fmt.Errorf("dirsearch: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	outFile := filepath.Join(tmp, "report.json")

	// TWO separate writers: exec pumps stdout/stderr on separate goroutines and
	// limitedWriter.Write is not goroutine-safe, so sharing one would race.
	var outTail, errTail limitedWriter
	outTail.buf = new([]byte)
	outTail.limit = 2048
	errTail.buf = new([]byte)
	errTail.limit = 2048

	cmd := exec.CommandContext(runCtx, bin, buildDirsearchArgs(base, wordlist, outFile, cfg)...)
	cmd.Stdout = &outTail
	cmd.Stderr = &errTail

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("dirsearch: start: %w", err)
	}

	waitErr := cmd.Wait()
	tailStr := strings.TrimSpace(string(*outTail.buf) + "\n" + string(*errTail.buf))

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("dirsearch: timed out after %s", dirsearchHardTimeout)
	}

	rawReport, readErr := os.ReadFile(outFile)
	if readErr != nil {
		if os.IsNotExist(readErr) {
			return fmt.Errorf("dirsearch: missing report: %s", tailStr)
		}
		return fmt.Errorf("dirsearch: read report: %w", readErr)
	}
	var report struct {
		Results []struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
		} `json:"results"`
	}
	if err := json.Unmarshal(rawReport, &report); err != nil {
		return fmt.Errorf("dirsearch: read report: %w", err)
	}

	emitted := 0
	seen := make(map[string]bool)
	for _, r := range report.Results {
		u := r.URL
		if u == "" || seen[u] {
			continue
		}
		// dirsearch can report non-http schemes; keep only what the
		// discovered_urls contract can use.
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			continue
		}
		seen[u] = true
		if emitted >= maxUrls {
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
			return ctx.Err()
		case out <- f:
			emitted++
		}
	}

	if waitErr != nil && emitted == 0 {
		return fmt.Errorf("dirsearch: %w: %s", waitErr, tailStr)
	}
	return nil
}

// normalizeBaseURL turns a raw target into the base URL dirsearch scans (-u)
// and the bare host used for Finding.Host. Empty -> "target required"; a
// leading "-" or any comma is rejected (dirsearch would swallow a leading dash
// as a flag, and a comma is never a valid host). A missing scheme defaults to
// https://. Returns "scheme://host/path" (trailing slash stripped) and the
// hostname.
func normalizeBaseURL(raw string) (string, string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("target required")
	}
	if strings.HasPrefix(s, "-") || strings.Contains(s, ",") {
		return "", "", fmt.Errorf("dirsearch: invalid target %q", raw)
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return "", "", fmt.Errorf("dirsearch: invalid target %q", raw)
	}
	return u.Scheme + "://" + u.Host + strings.TrimRight(u.Path, "/"), u.Hostname(), nil
}

// limitedWriter buffers output, keeping at most `limit` bytes.
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
