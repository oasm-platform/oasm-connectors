package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
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
//
// Exit-code semantics (wpscan v3.x): 0 = OK, 5 = VULNERABLE — both are success.
// 1 = CLI option error, 2 = interrupted, 3 = exception, 4 = error. stdout is
// valid JSON in every case, so it is parsed regardless of the exit code; a
// parseable stdout wins over a nonzero exit. Only unparseable stdout with a
// nonzero exit is fatal.
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

	cfg, err := loadWpscanConfig()
	if err != nil {
		return err
	}

	var stderr limitedWriter
	stderr.buf = new([]byte)
	stderr.limit = 2048

	var stdout bytes.Buffer
	cmd := exec.CommandContext(ctx, bin, buildWpscanArgs(target, cfg)...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	tail := strings.TrimSpace(string(*stderr.buf))

	var scanResult wpscanOutput
	if err := json.Unmarshal(stdout.Bytes(), &scanResult); err != nil {
		// Unparseable stdout: fatal when the process failed; otherwise the
		// stream simply held no findings.
		if runErr != nil {
			if tail != "" {
				return fmt.Errorf("wpscan: %w: %s", runErr, tail)
			}
			return fmt.Errorf("wpscan: %w", runErr)
		}
		return fmt.Errorf("wpscan: invalid JSON output: %w", err)
	}

	if scanResult.ScanAborted != "" {
		return fmt.Errorf("wpscan: scan aborted: %s (target: %s)", scanResult.ScanAborted, scanResult.TargetURL)
	}
	if scanResult.NotFullyConfigured != "" {
		return fmt.Errorf("wpscan: not fully configured: %s", scanResult.NotFullyConfigured)
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

// --- WPScan JSON structures (real v3.x schema) ---

type wpscanOutput struct {
	TargetURL          string                     `json:"target_url"`
	ScanAborted        string                     `json:"scan_aborted"`
	NotFullyConfigured string                     `json:"not_fully_configured"`
	Version            *componentVersion          `json:"version"`
	Plugins            map[string]wpscanComponent `json:"plugins"`
	Themes             map[string]wpscanComponent `json:"themes"`
	MainTheme          *wpscanComponent           `json:"main_theme"`
}

type wpscanComponent struct {
	Slug            string            `json:"slug"`
	Version         *componentVersion `json:"version"`
	Vulnerabilities []wpscanVuln      `json:"vulnerabilities"`
}

type componentVersion struct {
	Number          string       `json:"number"`
	Vulnerabilities []wpscanVuln `json:"vulnerabilities"`
}

type wpscanVuln struct {
	Title      string              `json:"title"`
	CVSS       *wpscanCVSS         `json:"cvss"`
	FixedIn    string              `json:"fixed_in"`
	References map[string][]string `json:"references"`
}

type wpscanCVSS struct {
	Score  json.RawMessage `json:"score"` // string OR number
	Vector string          `json:"vector"`
}

// --- Finding extraction ---

// extractFindings covers all 7 locations where wpscan reports vulnerabilities:
// core version, plugins, plugin versions, themes, theme versions, main theme,
// and main-theme version.
func extractFindings(result wpscanOutput, target string) []connector.Finding {
	var findings []connector.Finding

	if result.Version != nil {
		findings = appendVulns(findings, result.Version.Vulnerabilities, target)
	}

	for _, slug := range sortedKeys(result.Plugins) {
		comp := result.Plugins[slug]
		findings = appendVulns(findings, comp.Vulnerabilities, target)
		if comp.Version != nil {
			findings = appendVulns(findings, comp.Version.Vulnerabilities, target)
		}
	}

	for _, slug := range sortedKeys(result.Themes) {
		comp := result.Themes[slug]
		findings = appendVulns(findings, comp.Vulnerabilities, target)
		if comp.Version != nil {
			findings = appendVulns(findings, comp.Version.Vulnerabilities, target)
		}
	}

	if result.MainTheme != nil {
		findings = appendVulns(findings, result.MainTheme.Vulnerabilities, target)
		if result.MainTheme.Version != nil {
			findings = appendVulns(findings, result.MainTheme.Version.Vulnerabilities, target)
		}
	}

	return findings
}

func appendVulns(dst []connector.Finding, vulns []wpscanVuln, target string) []connector.Finding {
	for _, v := range vulns {
		if f, ok := toFinding(v, target); ok {
			dst = append(dst, f)
		}
	}
	return dst
}

func sortedKeys(m map[string]wpscanComponent) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// --- Severity / CVSS ---

// severityFromRawScore maps a CVSS base score (JSON string or number) to the
// SDK severity enum by band. Absent or unparseable scores are "info".
func severityFromRawScore(raw json.RawMessage) string {
	score, ok := parseCVSSScore(raw)
	if !ok {
		return "info"
	}
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score >= 0.1:
		return "low"
	default:
		return "info"
	}
}

// parseCVSSScore accepts a CVSS score encoded as a JSON string ("7.5") or a
// JSON number (7.5). Missing/null/empty/unparseable yields ok=false.
func parseCVSSScore(raw json.RawMessage) (float64, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" || s == "null" {
		return 0, false
	}
	s = strings.Trim(s, `"`)
	if s == "" {
		return 0, false
	}
	score, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	return score, true
}

// --- Finding mapping ---

func toFinding(v wpscanVuln, target string) (connector.Finding, bool) {
	if strings.TrimSpace(v.Title) == "" {
		return connector.Finding{}, false
	}

	f := connector.Finding{
		Name:      v.Title,
		Severity:  "info",
		MatchedAt: target,
		Timestamp: time.Now(),
	}

	if v.CVSS != nil {
		f.Severity = severityFromRawScore(v.CVSS.Score)
		if score, ok := parseCVSSScore(v.CVSS.Score); ok {
			f.CVSSScore = score
		}
		f.CVSSMetrics = v.CVSS.Vector
	}

	if v.FixedIn != "" {
		f.Solution = "Fixed in " + v.FixedIn
	}

	if len(v.References) > 0 {
		// Flatten the references map into a deterministic list: sorted keys,
		// values in their listed order, prefixed with the reference kind.
		keys := make([]string, 0, len(v.References))
		for k := range v.References {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, ref := range v.References[k] {
				f.References = append(f.References, k+":"+ref)
			}
		}
	}

	f.CVEID = append(f.CVEID, v.References["cve"]...)

	return f, true
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
