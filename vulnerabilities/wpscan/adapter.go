package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// WpscanAdapter runs WPScan and streams normalised findings.
type WpscanAdapter struct{}

// Validate is a no-op; upstream validates inputs.
func (a WpscanAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

// Execute runs wpscan --url <target> --format json and streams each
// vulnerability as a normalized Finding to out.
func (a WpscanAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	target, _ := inputs["target"].(string)
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("target required")
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	bin := os.Getenv("WPSCAN_BIN")
	if bin == "" {
		bin = "wpscan"
	}

	var stderr limitedWriter
	stderr.buf = new([]byte)
	stderr.limit = 2048

	cmd := exec.CommandContext(ctx, bin,
		"--url", target,
		"--format", "json",
		"--no-banner",
		"--random-user-agent",
	)
	cmd.Stderr = &stderr

	outBytes, err := cmd.Output()
	if err != nil {
		tail := string(*stderr.buf)
		if tail != "" {
			return fmt.Errorf("wpscan: %w\n%s", err, tail)
		}
		return fmt.Errorf("wpscan: %w", err)
	}

	// Parse the single JSON blob.
	var scanResult wpscanOutput
	if err := json.Unmarshal(outBytes, &scanResult); err != nil {
		return fmt.Errorf("wpscan: invalid JSON output: %w", err)
	}

	findings := extractFindings(scanResult, target)
	for _, f := range findings {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- f:
		}
	}

	return nil
}

// --- WPScan JSON structures ---

type wpscanOutput struct {
	Target          targetInfo                 `json:"target"`
	Vulnerabilities map[string][]wpscanVuln    `json:"vulnerabilities"`
	Plugins         map[string]wpscanComponent `json:"plugins"`
	Themes          map[string]wpscanComponent `json:"themes"`
	Version         *wpscanVersionInfo         `json:"version"`
}

type targetInfo struct {
	URL string `json:"url"`
}

type wpscanVuln struct {
	Title      string              `json:"title"`
	Severity   string              `json:"severity"`
	References map[string][]string `json:"references,omitempty"`
}

type wpscanComponent struct {
	Vulnerabilities map[string][]wpscanVuln `json:"vulnerabilities"`
}

type wpscanVersionInfo struct {
	Version         string       `json:"version"`
	Vulnerabilities []wpscanVuln `json:"vulnerabilities"`
}

// --- Finding extraction ---

func extractFindings(result wpscanOutput, target string) []connector.Finding {
	var findings []connector.Finding

	// Core vulnerabilities.
	for _, vulns := range result.Vulnerabilities {
		for _, v := range vulns {
			findings = append(findings, toFinding(v, target))
		}
	}

	// Plugin vulnerabilities.
	for _, comp := range result.Plugins {
		for _, vulns := range comp.Vulnerabilities {
			for _, v := range vulns {
				findings = append(findings, toFinding(v, target))
			}
		}
	}

	// Theme vulnerabilities.
	for _, comp := range result.Themes {
		for _, vulns := range comp.Vulnerabilities {
			for _, v := range vulns {
				findings = append(findings, toFinding(v, target))
			}
		}
	}

	// Version vulnerabilities.
	if result.Version != nil {
		for _, v := range result.Version.Vulnerabilities {
			findings = append(findings, toFinding(v, target))
		}
	}

	return findings
}

// normalizeSeverity lowercases a wpscan severity so it matches the SDK enum
// (wpscan emits "Critical", "High", "Medium", "Low"; the Finding contract is
// info|low|medium|high|critical). Unknown values fall back to info — same
// policy as the nessus adapter's mapSeverity.
func normalizeSeverity(s string) string {
	s = strings.ToLower(s)
	for _, sev := range connector.Severities {
		if s == sev {
			return s
		}
	}
	return "info"
}

func toFinding(v wpscanVuln, target string) connector.Finding {
	f := connector.Finding{
		Name:      v.Title,
		Severity:  normalizeSeverity(v.Severity),
		MatchedAt: target,
		Timestamp: time.Now(),
	}
	if len(v.References) > 0 {
		// Flatten the references map (url, wpvulndb, …) into a deterministic
		// list: sorted keys, then values in their listed order.
		keys := make([]string, 0, len(v.References))
		for k := range v.References {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			f.References = append(f.References, v.References[k]...)
		}
	}
	return f
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
