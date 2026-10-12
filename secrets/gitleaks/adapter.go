package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/oasm-platform/oasm-connectors/sdk/gitrepo"
)

// gitleaksConfig is the tool profile (configSchema in manifest.yaml).
type gitleaksConfig struct {
	// ScanHistory scans the last HistoryDepth commits instead of only the
	// current tree. Secrets deleted from the tree stay exposed in history.
	ScanHistory bool `json:"scanHistory"`
	// HistoryDepth bounds the history scan (and the clone depth).
	HistoryDepth int `json:"historyDepth"`
}

const (
	defaultHistoryDepth = 100
	maxHistoryDepth     = 5000
)

// GitleaksAdapter scans one repository for committed secrets with gitleaks.
//
// Inputs follow the SDK repository contract (sdk/gitrepo): the platform sends
// `repository` (https clone URL), `ref`, and `username`/`token` for private
// repositories. The repository is shallow-cloned into a temp dir, scanned with
// --redact (secret values never leave gitleaks), and removed afterwards.
type GitleaksAdapter struct {
	// clone and run are test seams; nil means the real implementations.
	clone func(ctx context.Context, in gitrepo.Inputs, opts gitrepo.Options) (*gitrepo.Checkout, error)
	run   func(ctx context.Context, args []string) (stderr string, err error)
}

// Validate checks the repository inputs early and cheaply.
func (a GitleaksAdapter) Validate(_ context.Context, inputs map[string]any) error {
	_, err := gitrepo.ParseInputs(inputs)
	return err
}

// Execute clones, scans and streams one Finding per leak.
//
// gitleaks runs with --exit-code 0: "leaks found" is the normal outcome of a
// scan, not a failure, so a nonzero exit means the tool itself failed.
func (a GitleaksAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	in, err := gitrepo.ParseInputs(inputs)
	if err != nil {
		return err
	}
	cfg, err := connector.LoadConfig[gitleaksConfig](ctx)
	if err != nil {
		return err
	}
	depth := 1
	if cfg.ScanHistory {
		depth = clampDepth(cfg.HistoryDepth)
	}

	clone := a.clone
	if clone == nil {
		clone = gitrepo.Clone
	}
	checkout, err := clone(ctx, in, gitrepo.Options{Depth: depth})
	if err != nil {
		return err
	}
	defer func() { _ = checkout.Close() }()

	reportDir, err := os.MkdirTemp("", "oasm-gitleaks-report-")
	if err != nil {
		return fmt.Errorf("gitleaks: create report dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(reportDir) }()
	reportPath := filepath.Join(reportDir, "report.json")

	run := a.run
	if run == nil {
		run = runGitleaks
	}
	if stderr, err := run(ctx, buildArgs(cfg.ScanHistory, depth, checkout.Dir, reportPath)); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("gitleaks failed: %w%s", err, formatStderr(stderr))
	}

	data, err := os.ReadFile(reportPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("gitleaks: read report: %w", err)
	}
	leaks, err := parseReport(data)
	if err != nil {
		return err
	}

	for _, l := range leaks {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- toFinding(l, checkout.Dir, checkout.Commit):
		}
	}
	return nil
}

// buildArgs assembles the gitleaks command line. Tree scans use `dir` (the
// files as checked out); history scans use `git` over the cloned commits.
func buildArgs(history bool, depth int, dir, reportPath string) []string {
	var args []string
	if history {
		args = []string{"git", dir, "--log-opts", fmt.Sprintf("--max-count=%d", depth)}
	} else {
		args = []string{"dir", dir}
	}
	return append(args,
		"--report-format", "json",
		"--report-path", reportPath,
		"--redact",
		"--exit-code", "0",
		"--no-banner",
		"--log-level", "warn",
	)
}

func clampDepth(depth int) int {
	switch {
	case depth <= 0:
		return defaultHistoryDepth
	case depth > maxHistoryDepth:
		return maxHistoryDepth
	default:
		return depth
	}
}

// runGitleaks runs the gitleaks binary (GITLEAKS_BIN, default "gitleaks").
func runGitleaks(ctx context.Context, args []string) (string, error) {
	bin := os.Getenv("GITLEAKS_BIN")
	if bin == "" {
		bin = "gitleaks"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stderr.String(), err
}

func formatStderr(stderr string) string {
	stderr = strings.TrimSpace(stderr)
	if stderr == "" {
		return ""
	}
	const max = 500
	if len(stderr) > max {
		stderr = stderr[:max] + "…"
	}
	return ": " + stderr
}
