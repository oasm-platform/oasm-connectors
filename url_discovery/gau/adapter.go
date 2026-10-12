package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// gauHardTimeout bounds the whole gau process. It is a safety net for gau's
// leaky per-request timeout (observed to wedge well past --timeout); the
// manifest's resourceDefaults.timeoutSeconds (900s) is comfortably above it so
// the adapter fails cleanly before the container is killed.
const gauHardTimeout = 10 * time.Minute

// GauAdapter runs gau (GetAllUrls, github.com/lc/gau) and streams each discovered
// URL as one connector.Finding (Name=URL, Severity=info, MatchedAt=URL, Host=domain).
//
// ponytail: one Finding per URL keeps the SDK contract (Finding-only output);
// ceiling: the SDK sends one gRPC Result message per finding (sdk/runtime), so
// thousands of URLs = thousands of messages; upgrade path = add an optional
// raw-data channel to the SDK. The worker aggregates Finding.Name into
// jobs_registry.DiscoveredUrl for category url_discovery.
type GauAdapter struct{}

// Validate is a no-op; upstream validates inputs.
func (a GauAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

// Execute runs gau and streams one Finding per unique discovered URL.
//
// Exit-code semantics: gau v2.2.4's exit code is unreliable — it returns 0 even
// when every provider fails — so a nonzero exit alone is not fatal. Fatal only
// when the process fails AND produced no output: the error carries the stderr
// tail. A nonzero exit WITH partial output is treated as success (partial
// results are still useful). A hard timeout is always reported as an error,
// even with partial output, because the run is incomplete. Exit 0 with zero
// URLs is a clean, zero-findings success — an empty archive result, not a
// failure.
func (a GauAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	raw, _ := inputs["target"].(string)
	target := connector.HostOnly(raw)
	if target == "" {
		return fmt.Errorf("target required")
	}
	// The target is the last positional argv element and gau parses flags
	// interspersed, so a target starting with "-" would be swallowed as a gau
	// flag (e.g. "--o=out.txt" redirects output to a file) and the run would
	// report a silent zero-finding success.
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("gau: invalid target %q", raw)
	}

	bin := os.Getenv("GAU_BIN")
	if bin == "" {
		bin = "gau"
	}

	cfg, err := connector.LoadConfig[gauConfig](ctx)
	if err != nil {
		return err
	}

	runCtx, cancel := context.WithTimeout(ctx, gauHardTimeout)
	defer cancel()

	stderr := connector.NewTailWriter(2048)

	cmd := exec.CommandContext(runCtx, bin, buildGauArgs(target, cfg)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("gau: stdout pipe: %w", err)
	}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("gau: start: %w", err)
	}

	emitted := 0
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
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
		case out <- f:
			emitted++
		}
	}
	scanErr := scanner.Err()

	waitErr := cmd.Wait()
	tail := stderr.String()

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("gau: timed out after %s", gauHardTimeout)
	}
	if waitErr != nil && emitted == 0 {
		if tail != "" {
			return fmt.Errorf("gau: %w: %s", waitErr, tail)
		}
		return fmt.Errorf("gau: %w", waitErr)
	}
	if scanErr != nil {
		return fmt.Errorf("gau: reading output: %w", scanErr)
	}
	return nil
}
