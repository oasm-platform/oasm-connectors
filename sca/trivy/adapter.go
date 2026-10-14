package main

import (
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

// trivyConfig is the tool profile (configSchema in manifest.yaml).
type trivyConfig struct {
	// Scanners selects what Trivy looks for: vuln (dependencies), misconfig
	// (IaC: Dockerfile, Kubernetes, Terraform…) and secret. Empty means
	// defaultScanners — secrets are left to the gitleaks job of the same
	// workflow unless asked for.
	Scanners []string `json:"scanners"`
	// Severity limits the reported findings, in platform severities
	// (info = Trivy's UNKNOWN). Empty means all.
	Severity []string `json:"severity"`
	// IgnoreUnfixed drops vulnerabilities that have no fixed version yet.
	IgnoreUnfixed bool `json:"ignoreUnfixed"`
	// SkipDirs are repository-relative directories or globs not scanned.
	SkipDirs []string `json:"skipDirs"`
}

var (
	defaultScanners = []string{"vuln", "misconfig"}
	allowedScanners = map[string]bool{"vuln": true, "misconfig": true, "secret": true}

	// trivySeverities maps platform severities onto Trivy's --severity values.
	trivySeverities = map[string]string{
		"info":     "UNKNOWN",
		"low":      "LOW",
		"medium":   "MEDIUM",
		"high":     "HIGH",
		"critical": "CRITICAL",
	}
)

// TrivyAdapter scans one repository with `trivy fs`: vulnerable dependencies
// from lockfiles and manifests, IaC misconfigurations and, optionally,
// secrets.
//
// Inputs follow the SDK repository contract (sdk/gitrepo): the platform sends
// `repository` (https clone URL), `ref`, and `username`/`token` for private
// repositories. The repository is shallow-cloned into a temp dir, scanned,
// and removed afterwards; Trivy itself never sees the credentials. The
// databases live in a cache shared by every container of the image (db.go).
type TrivyAdapter struct {
	// clone, run, lock and cacheDir are test seams; zero values mean the real
	// implementations.
	clone    func(ctx context.Context, in gitrepo.Inputs, opts gitrepo.Options) (*gitrepo.Checkout, error)
	run      runFunc
	lock     lockFunc
	cacheDir string
}

// runFunc runs trivy with args and extra environment variables.
type runFunc func(ctx context.Context, args, env []string) (stderr string, err error)

// Validate checks the repository inputs and the profile early and cheaply.
func (a TrivyAdapter) Validate(ctx context.Context, inputs map[string]any) error {
	if _, err := gitrepo.ParseInputs(inputs); err != nil {
		return err
	}
	cfg, err := connector.LoadConfig[trivyConfig](ctx)
	if err != nil {
		return err
	}
	_, err = buildArgs(cfg, "dir", "report.json", "cache")
	return err
}

// Execute clones, scans and streams one Finding per vulnerability,
// misconfiguration or secret.
//
// trivy runs with --exit-code 0: "issues found" is the normal outcome of a
// scan, not a failure, so a nonzero exit means the tool itself failed.
func (a TrivyAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	in, err := gitrepo.ParseInputs(inputs)
	if err != nil {
		return err
	}
	cfg, err := connector.LoadConfig[trivyConfig](ctx)
	if err != nil {
		return err
	}

	reportDir, err := os.MkdirTemp("", "oasm-trivy-report-")
	if err != nil {
		return fmt.Errorf("trivy: create report dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(reportDir) }()
	reportPath := filepath.Join(reportDir, "report.json")

	clone := a.clone
	if clone == nil {
		clone = gitrepo.Clone
	}
	checkout, err := clone(ctx, in, gitrepo.Options{Depth: 1})
	if err != nil {
		return err
	}
	defer func() { _ = checkout.Close() }()

	cacheDir := a.cacheDir
	if cacheDir == "" {
		cacheDir = defaultCacheDir()
	}
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return fmt.Errorf("trivy: create cache dir: %w", err)
	}
	args, err := buildArgs(cfg, checkout.Dir, reportPath, cacheDir)
	if err != nil {
		return err
	}
	run := a.run
	if run == nil {
		run = runTrivy
	}
	lock := a.lock
	if lock == nil {
		lock = flockFile
	}

	if err := updateDBs(ctx, cacheDir, checkout.Dir, hasJavaArchives(checkout.Dir), run, lock); err != nil {
		return err
	}
	// Shared: concurrent scans are fine, an update has to wait for them.
	unlock, err := lock(ctx, filepath.Join(cacheDir, lockFileName), false, 0)
	if err != nil {
		return err
	}
	stderr, err := run(ctx, args, nil)
	unlock()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("trivy failed: %w%s", err, formatStderr(stderr))
	}

	data, err := os.ReadFile(reportPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("trivy: read report: %w", err)
	}
	findings, err := parseReport(data, checkout.Commit)
	if err != nil {
		return err
	}

	for _, f := range findings {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- f:
		}
	}
	return nil
}

// buildArgs assembles the `trivy fs` command line, rejecting unknown scanners
// and severities so a bad profile fails as a configuration error instead of
// a Trivy usage error. The scan never updates anything: updateDBs refreshed
// the databases, and the rego checks embedded in the binary are used.
func buildArgs(cfg *trivyConfig, dir, reportPath, cacheDir string) ([]string, error) {
	scanners := cfg.Scanners
	if len(scanners) == 0 {
		scanners = defaultScanners
	}
	for _, s := range scanners {
		if !allowedScanners[s] {
			return nil, fmt.Errorf("fatal: unknown scanner %q (allowed: vuln, misconfig, secret)", s)
		}
	}

	args := append([]string{
		"fs",
		"--format", "json",
		"--output", reportPath,
		"--scanners", strings.Join(scanners, ","),
		"--exit-code", "0",
		"--skip-db-update",
		"--skip-java-db-update",
		"--skip-check-update",
		// The SDK bounds the run with the job's context; Trivy's own 5m
		// default would abort large repositories long before that.
		"--timeout", "25m",
	}, commonArgs(cacheDir)...)
	if len(cfg.Severity) > 0 {
		severities := make([]string, 0, len(cfg.Severity))
		for _, s := range cfg.Severity {
			mapped, ok := trivySeverities[strings.ToLower(strings.TrimSpace(s))]
			if !ok {
				return nil, fmt.Errorf("fatal: unknown severity %q (allowed: info, low, medium, high, critical)", s)
			}
			severities = append(severities, mapped)
		}
		args = append(args, "--severity", strings.Join(severities, ","))
	}
	if cfg.IgnoreUnfixed {
		args = append(args, "--ignore-unfixed")
	}
	for _, d := range cfg.SkipDirs {
		if d = strings.TrimSpace(d); d != "" {
			// --flag=value: a value starting with "-" stays a value.
			args = append(args, "--skip-dirs="+d)
		}
	}
	return append(args, dir), nil
}

// runTrivy runs the trivy binary (TRIVY_BIN, default "trivy") with env added
// to the connector's environment.
func runTrivy(ctx context.Context, args, env []string) (string, error) {
	bin := os.Getenv("TRIVY_BIN")
	if bin == "" {
		bin = "trivy"
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	// Trivy logs INFO lines before the fatal error; keep the tail, which is
	// where the cause is.
	stderr := connector.NewTailWriter(2048)
	cmd.Stderr = stderr
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
		stderr = "…" + stderr[len(stderr)-max:]
	}
	return ": " + stderr
}
