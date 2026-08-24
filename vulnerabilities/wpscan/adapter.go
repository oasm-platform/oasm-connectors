package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// WpscanAdapter runs WPScan and streams normalised findings.
type WpscanAdapter struct{}

// Validate is a no-op; upstream validates inputs.
func (a WpscanAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

// Execute runs wpscan --url <target> --format json and streams each
// vulnerability as a JSONL line to out.
func (a WpscanAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- []byte) error {
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
		data, err := json.Marshal(f)
		if err != nil {
			continue
		}
		out <- data
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

type finding struct {
	Title    string              `json:"title"`
	Severity string              `json:"severity"`
	Source   string              `json:"source"`
	Target   string              `json:"target"`
	Refs     map[string][]string `json:"references,omitempty"`
}

func extractFindings(result wpscanOutput, target string) []finding {
	var findings []finding

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

func toFinding(v wpscanVuln, target string) finding {
	f := finding{
		Title:    v.Title,
		Severity: v.Severity,
		Source:   "wpscan",
		Target:   target,
	}
	if len(v.References) > 0 {
		f.Refs = v.References
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
