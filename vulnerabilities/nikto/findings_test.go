package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// TestParseRealNiktoStdout pins the parser against output captured from a real
// `nikto.pl 2.6.1` run (testdata/real-cve-stdout.txt: the connector image
// scanning an nginx:alpine container with -Tuning 236 -C all). Synthetic
// fixtures can drift from the upstream format; this one cannot.
//
// The capture deliberately contains both kinds of check id: 000024/007342/007352
// are in db_tests, 013587 is defined in nikto_headers.plugin and is absent from
// it. That split is what exercises the enrichment's fallback path.
func TestParseRealNiktoStdout(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "real-cve-stdout.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	out := make(chan connector.Finding, 64)
	emitted, scanErr := scanItems(t.Context(), bytes.NewReader(raw), "http://nikto-target", out)
	close(out)
	if scanErr != nil {
		t.Fatalf("scanItems: %v", scanErr)
	}
	if emitted != 8 {
		t.Fatalf("emitted = %d, want 8 (the real run reported 8 items)", emitted)
	}

	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	if len(findings) != 8 {
		t.Fatalf("got %d findings, want 8", len(findings))
	}

	// Every real item was prefixed with a root-relative path, so every finding
	// must resolve onto the target host. Most resolve to "/"; the CVE-backed
	// 000024 item points at the concrete CGI path it probed.
	for i, f := range findings {
		if !strings.HasPrefix(f.MatchedAt, "http://nikto-target/") {
			t.Errorf("finding %d MatchedAt = %q, want a URL under http://nikto-target/", i, f.MatchedAt)
		}
		if err := f.Validate(); err != nil {
			t.Errorf("finding %d invalid: %v", i, err)
		}
	}

	// Item order varies between runs (nikto walks a Perl hash), so assert on the
	// set of names rather than on positions.
	byName := map[string]connector.Finding{}
	for _, f := range findings {
		byName[f.Name] = f
	}
	for _, want := range []string{
		"Suggested security header missing: strict-transport-security.",
		"Suggested security header missing: content-security-policy.",
		"Suggested security header missing: x-content-type-options.",
		"X-Frame-Options header is deprecated and was replaced with the Content-Security-Policy HTTP header with the frame-ancestors directive.",
	} {
		if _, ok := byName[want]; !ok {
			t.Errorf("missing real finding %q; got %v", want, keysOf(byName))
		}
	}

	// A header-disclosure item keeps the advisory URL nikto appended after
	// " See: ".
	hsts := byName["Suggested security header missing: strict-transport-security."]
	if !slices.Contains(hsts.References, "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security") {
		t.Errorf("hsts References = %v", hsts.References)
	}
}

// TestRealStdout_EnrichmentFromDatabase is the regression test for the CVE gap:
// nikto prints expanded advisory URLs, so the old whole-token CVE regex left
// CVEID empty on every real scan. The CVE must now be recovered from the
// database's refs field.
func TestRealStdout_EnrichmentFromDatabase(t *testing.T) {
	if loadNiktoDB() == nil {
		t.Skip("db_tests not available in this environment")
	}
	f, ok := parseItemLine(
		`+ [000024] /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage. See: https://nvd.nist.gov/vuln/detail/CVE-2000-0709`,
		"http://nikto-target")
	if !ok {
		t.Fatal("expected a finding")
	}
	// CVE from the URL stdout prints.
	if !slices.Contains(f.CVEID, "CVE-2000-0709") {
		t.Errorf("CVEID = %v, want CVE-2000-0709 (from the stdout advisory URL)", f.CVEID)
	}
	// Category from the database's tuning field (000024 is tuning "6", Denial
	// of Service).
	if !slices.Contains(f.Tags, "category:Denial of Service") {
		t.Errorf("Tags = %v, want category:Denial of Service", f.Tags)
	}
	if f.Severity != "medium" {
		t.Errorf("Severity = %q, want medium (tuning 6)", f.Severity)
	}
	if !slices.Contains(f.Tags, "severity-source:tuning:6") {
		t.Errorf("Tags = %v, want severity-source:tuning:6", f.Tags)
	}

	// A plugin-only id has no database row: no category, keyword severity.
	g, ok := parseItemLine(
		`+ [013587] /: Suggested security header missing: permissions-policy. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy`,
		"http://nikto-target")
	if !ok {
		t.Fatal("expected a finding")
	}
	for _, tag := range g.Tags {
		if strings.HasPrefix(tag, "category:") {
			t.Errorf("plugin-only id 013587 must have no category tag, got %v", g.Tags)
		}
	}
	if !slices.Contains(g.Tags, "severity-source:keyword") {
		t.Errorf("Tags = %v, want the keyword source (no database row exists)", g.Tags)
	}
}

// TestCategoriesCoverRealStdout asserts every check in the real capture ends up
// with either a database-derived category or the explicit keyword fallback —
// never a silently unclassified severity.
func TestCategoriesCoverRealStdout(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "real-cve-stdout.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	for _, line := range splitLines(string(raw)) {
		f, ok := parseItemLine(line, "http://nikto-target")
		if !ok {
			continue
		}
		hasCategory := slices.ContainsFunc(f.Tags, func(t string) bool {
			return strings.HasPrefix(t, "category:")
		})
		hasSource := slices.ContainsFunc(f.Tags, func(t string) bool {
			return strings.HasPrefix(t, "severity-source:")
		})
		if !hasSource {
			t.Errorf("finding %q has no severity-source tag: %v", f.Name, f.Tags)
		}
		if !hasCategory && !slices.Contains(f.Tags, "severity-source:keyword-fallback") && !strings.HasPrefix(severitySourceOf(f), "keyword") {
			t.Errorf("finding %q is unclassified: %v", f.Name, f.Tags)
		}
	}
}

// severitySourceOf returns the severity-source tag of a finding, if any.
func severitySourceOf(f connector.Finding) string {
	for _, t := range f.Tags {
		if strings.HasPrefix(t, "severity-source:") {
			return strings.TrimPrefix(t, "severity-source:")
		}
	}
	return ""
}

func keysOf(m map[string]connector.Finding) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestParseRealNiktoStdout_NoFakeFindings proves the informational lines in the
// real capture (banner, Target IP/Hostname/Port/Platform, Server, the CGI note,
// the request summary and "1 host(s) tested") never become findings. 8 items
// reported by nikto == 8 findings is the assertion; this spells out why.
func TestParseRealNiktoStdout_NoFakeFindings(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "real-cve-stdout.txt"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	findings := 0
	for _, line := range splitLines(string(raw)) {
		if _, ok := parseItemLine(line, "http://nikto-target"); ok {
			findings++
		}
	}
	if findings != 8 {
		t.Fatalf("parsed %d result lines, want 8", findings)
	}
}

func splitLines(s string) []string {
	return strings.Split(s, "\n")
}
