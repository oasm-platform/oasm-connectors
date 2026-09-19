package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// Baseline is spider + passive scan only; full adds the active scanner. The
// active scanner attacks the target, so its hard timeout is generous while
// baseline stays tight.
const (
	zapBaselineHardTimeout = 15 * time.Minute
	zapFullHardTimeout     = 45 * time.Minute
)

// ZapAdapter runs OWASP ZAP via the Automation Framework and streams the
// alerts from its JSON report as normalized findings.
type ZapAdapter struct{}

// Validate is intentionally a no-op: inputs are validated upstream by the
// worker node against the connector's inputsSchema.
func (a *ZapAdapter) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

// Execute runs one ZAP scan against target and streams every alert to out.
//
// ZAP is invoked as `zap.sh -cmd -silent -autorun <plan>`; -cmd makes it exit
// when the plan finishes and -silent blocks its unsolicited startup egress
// (including update checks). Everything (plan, ZAP home, report) lives under
// one temp dir that is removed on return, so warm-pool reuse stays clean.
//
// Exit-code semantics: with -cmd -autorun ZAP exits 0 (clean), 1 (errors) or
// 2 (warnings). The JSON report is the source of truth — a parseable report
// wins over a nonzero exit (partial results are still useful). Only a missing
// report, an unparseable report, or the hard timeout is fatal.
func (a *ZapAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	raw, _ := inputs["target"].(string)
	target := normalizeTarget(raw)
	if target == "" {
		return fmt.Errorf("target required")
	}

	bin := os.Getenv("ZAP_BIN")
	if bin == "" {
		bin = "zap.sh"
	}

	cfg, err := loadZapConfig()
	if err != nil {
		return err
	}

	workDir, err := os.MkdirTemp("", "oasm-zap-*")
	if err != nil {
		return fmt.Errorf("zap: create work dir: %w", err)
	}
	// ZAP_KEEP_WORKDIR=1 keeps plan.yaml, the report and stderr on disk for
	// debugging a failed scan; otherwise the temp dir is always removed.
	defer func() {
		if os.Getenv("ZAP_KEEP_WORKDIR") != "" {
			log.Printf("zap: keeping work dir %s", workDir)
			return
		}
		_ = os.RemoveAll(workDir)
	}()

	reportPath := filepath.Join(workDir, "report.json")
	plan, err := buildAutomationPlan(target, cfg, reportPath)
	if err != nil {
		return err
	}
	planPath := filepath.Join(workDir, "plan.yaml")
	if err := os.WriteFile(planPath, plan, 0o600); err != nil {
		return fmt.Errorf("zap: write plan: %w", err)
	}

	hard := zapBaselineHardTimeout
	if strings.EqualFold(strings.TrimSpace(cfg.ScanMode), "full") {
		hard = zapFullHardTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, hard)
	defer cancel()

	var stderr limitedWriter
	stderr.buf = new([]byte)
	stderr.limit = 4096

	// ZAP needs a writable, isolated home dir; create it up front so -dir never
	// points at a path ZAP has to guess how to create.
	homeDir := filepath.Join(workDir, "home")
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		return fmt.Errorf("zap: create home dir: %w", err)
	}

	cmd := exec.CommandContext(runCtx, bin, "-cmd", "-silent", "-nostdout",
		"-autorun", planPath, "-dir", homeDir)
	cmd.Stderr = &stderr
	// ZAP is a shell script that spawns a JVM; kill the whole process group on
	// cancel/timeout or the JVM survives the container's warm-pool reuse.
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd.Process) }
	cmd.WaitDelay = 15 * time.Second

	runErr := cmd.Run()
	tail := strings.TrimSpace(string(*stderr.buf))

	if ctx.Err() != nil {
		return ctx.Err()
	}
	if runCtx.Err() == context.DeadlineExceeded {
		return fmt.Errorf("zap: timed out after %s", hard)
	}

	reportData, readErr := os.ReadFile(reportPath)
	if readErr != nil {
		if runErr != nil {
			if tail != "" {
				return fmt.Errorf("zap: %w: %s", runErr, tail)
			}
			return fmt.Errorf("zap: %w", runErr)
		}
		return fmt.Errorf("zap: no report produced: %w", readErr)
	}

	findings, err := parseReport(reportData, target)
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
