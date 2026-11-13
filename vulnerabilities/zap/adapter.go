package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	httphelper "github.com/oasm-platform/oasm-connectors/sdk/http"
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
	target := connector.WebURL(raw)
	if target == "" {
		return fmt.Errorf("target required")
	}

	bin := os.Getenv("ZAP_BIN")
	if bin == "" {
		bin = "zap.sh"
	}

	cfg, err := connector.LoadConfig[zapConfig](ctx)
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

	hard := zapHardTimeout(cfg)
	runCtx, cancel := context.WithTimeout(ctx, hard)
	defer cancel()

	stderr := connector.NewTailWriter(4096)

	// ZAP needs a writable, isolated home dir; create it up front so -dir never
	// points at a path ZAP has to guess how to create.
	homeDir := filepath.Join(workDir, "home")
	if err := os.MkdirAll(homeDir, 0o700); err != nil {
		return fmt.Errorf("zap: create home dir: %w", err)
	}

	args := []string{"-cmd", "-silent", "-nostdout", "-autorun", planPath, "-dir", homeDir}
	// ZAP's JVM ignores HTTP_PROXY; route it through the worker egress proxy.
	if proxy := httphelper.ProxyOrEnv(""); proxy != "" {
		args = append(args, zapProxyArgs(proxy)...)
	}
	cmd := exec.CommandContext(runCtx, bin, args...)
	cmd.Stderr = stderr
	// ZAP is a shell script that spawns a JVM; kill the whole process group on
	// cancel/timeout or the JVM survives the container's warm-pool reuse.
	setProcessGroup(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd.Process) }
	cmd.WaitDelay = 15 * time.Second

	runErr := cmd.Run()
	tail := stderr.String()

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

// zapProxyArgs sets ZAP's outbound HTTP proxy (network add-on options) from a
// proxy URL, moving URL userinfo into the proxy auth options.
func zapProxyArgs(proxy string) []string {
	u, err := url.Parse(proxy)
	if err != nil || u.Host == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		host, port = u.Host, "80"
	}
	const k = "network.connection.httpProxy."
	args := []string{"-config", k + "enabled=true", "-config", k + "host=" + host, "-config", k + "port=" + port}
	if u.User != nil {
		pass, _ := u.User.Password()
		args = append(args, "-config", k+"authEnabled=true",
			"-config", k+"username="+u.User.Username(), "-config", k+"password="+pass)
	}
	return args
}
