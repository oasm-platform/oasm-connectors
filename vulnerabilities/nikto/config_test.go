package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

func TestLoadNiktoConfig_EmptyIsZeroConfig(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadNiktoConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil zero config")
	}
	if cfg.Timeout != 0 || cfg.Tuning != "" {
		t.Fatalf("expected zero config, got %+v", cfg)
	}
}

func TestLoadNiktoConfig_ParsesCamelCaseKeys(t *testing.T) {
	t.Setenv("OASM_CONFIG", `{"tuning":"123b","ports":"80,443","ssl":true,"timeout":15,"headers":["X-Test: 1"],"noCookies":true,"followRedirects":true,"evasion":"1","username":"u","password":"p"}`)
	cfg, err := loadNiktoConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Tuning != "123b" {
		t.Errorf("Tuning = %q", cfg.Tuning)
	}
	if cfg.Ports != "80,443" {
		t.Errorf("Ports = %q", cfg.Ports)
	}
	if !cfg.SSL || !cfg.NoCookies || !cfg.FollowRedirect {
		t.Errorf("bool keys lost: %+v", cfg)
	}
	if cfg.Timeout != 15 {
		t.Errorf("Timeout = %d", cfg.Timeout)
	}
	if len(cfg.Headers) != 1 || cfg.Headers[0] != "X-Test: 1" {
		t.Errorf("Headers = %v", cfg.Headers)
	}
	if cfg.Evasion != "1" || cfg.Username != "u" || cfg.Password != "p" {
		t.Errorf("string keys lost: %+v", cfg)
	}
}

func TestLoadNiktoConfig_InvalidJSONErrors(t *testing.T) {
	t.Setenv("OASM_CONFIG", "{not json")
	_, err := loadNiktoConfig()
	if err == nil {
		t.Fatal("expected error for malformed OASM_CONFIG")
	}
	if !strings.Contains(err.Error(), "invalid OASM_CONFIG") {
		t.Fatalf("expected 'invalid OASM_CONFIG' in error, got: %s", err.Error())
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "https://example.com"},
		{"https://example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"example.com:8443", "https://example.com:8443"},
		{"https://example.com:8443/app", "https://example.com:8443/app"},
		{"  example.com  ", "https://example.com"},
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range cases {
		if got := normalizeTarget(tc.in); got != tc.want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestBuildNiktoArgs_Defaults asserts the always-present flags for a zero config.
// -maxtime is deliberately absent: the adapter imposes no scan budget of its
// own (see timeout_test.go), so an unset maxTime leaves nikto unbounded.
func TestBuildNiktoArgs_Defaults(t *testing.T) {
	got := buildNiktoArgs("https://example.com", &niktoConfig{}, "/tmp/nikto.conf")
	want := []string{"-h", "https://example.com", "-config", "/tmp/nikto.conf", "-nointeractive"}
	if !equalStrings(got, want) {
		t.Fatalf("default args = %v, want %v", got, want)
	}
}

// TestBuildNiktoArgs_FullConfig asserts the exact ordered vector for a fully
// populated config, and that zero/empty values stay omitted.
func TestBuildNiktoArgs_FullConfig(t *testing.T) {
	cfg := &niktoConfig{
		Tuning: "123b", Ports: "80,443", SSL: true, Root: "/app", Vhost: "internal.corp",
		UserAgent: "Mozilla/5.0", MaxTime: "10m", Timeout: 7, Pause: 2,
		Headers: []string{"X-Api-Key: k1", "  "}, NoLookup: true, NoCookies: true,
		FollowRedirect: true, No404: true, Evasion: "1234", Plugins: "tests(report:500)",
		Proxy: "http://127.0.0.1:8080", Username: "admin", Password: "s3cr3t",
	}
	got := buildNiktoArgs("https://example.com", cfg, "/tmp/nikto.conf")
	// -port and a full URI are mutually exclusive in nikto, so the https target
	// is reduced to a bare host and TLS is expressed with -ssl instead.
	want := []string{
		"-h", "example.com", "-config", "/tmp/nikto.conf", "-nointeractive",
		"-Tuning", "123b",
		"-port", "80,443",
		"-ssl",
		"-root", "/app",
		"-vhost", "internal.corp",
		"-useragent", "Mozilla/5.0",
		"-maxtime", "10m",
		"-timeout", "7",
		"-Pause", "2",
		"-Add-header", "X-Api-Key: k1",
		"-nolookup",
		"-nocookies",
		"-followredirects",
		"-no404",
		"-evasion", "1234",
		"-Plugins", "tests(report:500)",
		"-useproxy", "http://127.0.0.1:8080",
		"-id", "admin:s3cr3t",
	}
	if !equalStrings(got, want) {
		t.Fatalf("full args =\n%v\nwant\n%v", got, want)
	}
}

// TestBuildNiktoArgs_PortsRequireBareHost pins the nikto constraint that -port
// cannot be combined with a full URI (set_targets exits 1 on that combination):
// selecting ports must strip the scheme and the URL's own port, and TLS must be
// re-expressed with -ssl so an https target is not silently downgraded.
func TestBuildNiktoArgs_PortsRequireBareHost(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		cfg      *niktoConfig
		wantHost string
		wantSSL  bool
	}{
		{"https target with ports", "https://example.com", &niktoConfig{Ports: "80,443"}, "example.com", true},
		{"http target with ports", "http://example.com", &niktoConfig{Ports: "80"}, "example.com", false},
		{"URL port replaced by -port", "https://example.com:8443", &niktoConfig{Ports: "8443"}, "example.com", true},
		{"path dropped for -port", "https://example.com/app", &niktoConfig{Ports: "443"}, "example.com", true},
		{"no ports keeps full URL", "https://example.com", &niktoConfig{}, "https://example.com", false},
		{"no ports keeps explicit -ssl", "http://example.com", &niktoConfig{SSL: true}, "http://example.com", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := buildNiktoArgs(tc.target, tc.cfg, "/tmp/nikto.conf")
			host := argValue(args, "-h")
			if host != tc.wantHost {
				t.Errorf("-h = %q, want %q (args %v)", host, tc.wantHost, args)
			}
			if got := hasFlag(args, "-ssl"); got != tc.wantSSL {
				t.Errorf("-ssl present = %v, want %v (args %v)", got, tc.wantSSL, args)
			}
			// The invariant nikto enforces: -port and a full URI never coexist.
			if hasFlag(args, "-port") && strings.HasPrefix(host, "http") {
				t.Errorf("-h %q is a full URI while -port is set — nikto exits 1", host)
			}
		})
	}
}

// argValue returns the value following the first occurrence of flag.
func argValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

// TestNiktoExecute_PassesConfigFile proves the generated config reaches nikto
// with PROMPTS=no and UPDATES=no — without them a scan blocks on stdin.
func TestNiktoExecute_PassesConfigFile(t *testing.T) {
	bin := ensureFakeNikto(t)
	t.Setenv("NIKTO_BIN", bin)
	t.Setenv("FAKE_MODE", "empty")
	t.Setenv("OASM_CONFIG", "")

	cfgCopy := filepath.Join(t.TempDir(), "nikto.conf.copy")
	t.Setenv("FAKE_CONFIG_COPY", cfgCopy)

	out := make(chan connector.Finding, 8)
	if err := (NiktoAdapter{}).Execute(context.Background(), map[string]any{"target": "example.com"}, out); err != nil {
		t.Fatalf("execute: %v", err)
	}
	close(out)

	raw, err := os.ReadFile(cfgCopy)
	if err != nil {
		t.Fatalf("fake nikto did not receive a readable -config: %v", err)
	}
	body := string(raw)
	for _, want := range []string{"PROMPTS=no", "UPDATES=no", "CHECKMETHODS=GET", "@@DEFAULT="} {
		if !strings.Contains(body, want) {
			t.Errorf("generated config missing %q:\n%s", want, body)
		}
	}
}

// --- severity rubric ---

// The keyword rubric is now only the fallback for ids absent from db_tests
// (nikto's 60 plugin-only ids). Its bands are pinned here directly against
// resolveSeverityFromMessage so they stay covered regardless of whether the
// database is present.
func TestResolveSeverityFromMessage_Bands(t *testing.T) {
	cases := []struct{ message, want string }{
		{"EZShopper loadpage CGI command execution", "critical"},
		{"Some versions of PHProjekt allow remote file inclusions.", "critical"},
		{"Geeklog contains a SQL injection vulnerability that lets a remote attacker reset admin password.", "high"},
		{"Resin 2.1.2 view_source.jsp allows any file to be viewed by using directory traversal.", "high"},
		{"Horde allows phpinfo() to be run, which gives detailed system information.", "medium"},
		{"MoinMoin 1.1 and prior contain at least two XSS vulnerabilities.", "medium"},
		{"Directory indexing is enabled on /backup/.", "medium"},
		{"The anti-clickjacking X-Frame-Options header is not present.", "low"},
		{"Uncommon header 'x-powered-by' found, with contents: PHP/8.1.", "low"},
		{"Totally unclassified widget anomaly.", "medium"},
	}
	for _, tc := range cases {
		if got, _ := resolveSeverityFromMessage(tc.message); got != tc.want {
			t.Errorf("resolveSeverityFromMessage(%q) = %q, want %q", tc.message, got, tc.want)
		}
	}
}

func TestResolveSeverityFromMessage_Source(t *testing.T) {
	if _, src := resolveSeverityFromMessage("Backup file found, source code disclosure."); src != "" {
		t.Errorf("keyword match must report an empty source, got %q", src)
	}
	if _, src := resolveSeverityFromMessage("Totally unclassified widget anomaly."); src != "keyword-fallback" {
		t.Errorf("unmatched message source = %q, want keyword-fallback", src)
	}
}

// A finding whose id is in the database must take its severity from the tuning
// classification, not from the wording of the message. The message below would
// score "low" on the keyword rubric ("header"), but id 007352 is a
// Misconfiguration check, which the database grades "medium".
func TestResolveSeverity_PrefersDatabaseOverKeywords(t *testing.T) {
	if loadNiktoDB() == nil {
		t.Skip("db_tests not available in this environment")
	}
	sev, kind, cats := resolveSeverity("007352", "The X-File header is not present.")
	if sev != "medium" {
		t.Errorf("severity = %q, want medium (from tuning 2)", sev)
	}
	if !strings.HasPrefix(kind, "tuning:") {
		t.Errorf("source = %q, want a tuning: prefix", kind)
	}
	if !slices.Contains(cats, "Misconfiguration / Default File") {
		t.Errorf("categories = %v, want Misconfiguration", cats)
	}
}

// An id absent from the database falls back to the keyword rubric.
func TestResolveSeverity_FallsBackForPluginOnlyId(t *testing.T) {
	// 013587 is defined in nikto_headers.plugin, not in db_tests.
	if _, ok := dbEntryFor("013587"); ok {
		t.Skip("013587 unexpectedly present in this db_tests build")
	}
	sev, kind, cats := resolveSeverity("013587", "Suggested security header missing: content-security-policy.")
	if kind != "keyword" && kind != "keyword-fallback" {
		t.Errorf("source = %q, want a keyword source", kind)
	}
	if sev == "" {
		t.Error("severity must not be empty")
	}
	if cats != nil {
		t.Errorf("categories = %v, want nil for a plugin-only id", cats)
	}
}

func TestParseItemLine_TagsFallbackFindings(t *testing.T) {
	f, ok := parseItemLine("+ [000024] Totally unclassified widget anomaly.", "https://example.com")
	if !ok {
		t.Fatal("expected a finding")
	}
	if f.Severity != "medium" {
		t.Errorf("Severity = %q, want medium", f.Severity)
	}
	if !slices.Contains(f.Tags, "severity:heuristic") {
		t.Errorf("fallback tags missing: %v", f.Tags)
	}
}

func TestParseItemLine_IgnoresNonResultLines(t *testing.T) {
	for _, line := range []string{
		"- Nikto v2.6.1",
		"+ Target IP:          93.184.216.34",
		"+ Target Hostname:    example.com",
		"+ Server: nginx/1.24.0",
		"+ 2 host(s) tested",
		"---------------------------------------------------------------------------",
		"+ [000024]",
	} {
		if _, ok := parseItemLine(line, "https://example.com"); ok {
			t.Errorf("line %q must not produce a finding", line)
		}
	}
}

// TestParseItemLine_NoRefsOnStdout covers a result whose stdout line has no
// " See: " suffix: the body is entirely the message and stdout supplies no
// references. That no longer means the finding has no references at all — when
// db_tests is present its refs field supplies them, which is the whole point of
// the enrichment (id 000024 is a CVE-backed check whose stdout form prints only
// the advisory URL). The message and MatchedAt parsing is what this test pins.
func TestParseItemLine_NoRefsOnStdout(t *testing.T) {
	f, ok := parseItemLine("+ [000024] /backup.zip: Backup file found, source code disclosure.", "https://example.com")
	if !ok {
		t.Fatal("expected a finding")
	}
	if f.Name != "Backup file found, source code disclosure." {
		t.Errorf("Name = %q", f.Name)
	}
	if f.MatchedAt != "https://example.com/backup.zip" {
		t.Errorf("MatchedAt = %q, want https://example.com/backup.zip", f.MatchedAt)
	}

	if loadNiktoDB() == nil {
		// Without the database there is no enrichment source, so stdout's
		// absence of references is final.
		if len(f.References) != 0 {
			t.Errorf("References = %v, want none without a database", f.References)
		}
		return
	}
	// With the database, id 000024 must contribute its CVE reference and match
	// the CVEID field — the regression this enrichment exists to fix.
	if !slices.Contains(f.References, "CVE-2000-0709") {
		t.Errorf("References = %v, want the database's CVE-2000-0709", f.References)
	}
	if !slices.Contains(f.CVEID, "CVE-2000-0709") {
		t.Errorf("CVEID = %v, want CVE-2000-0709", f.CVEID)
	}
}

func TestSplitURIPrefix(t *testing.T) {
	cases := []struct{ in, msg, uri string }{
		{"/admin/: Admin login page found.", "Admin login page found.", "/admin/"},
		{"/index.php: PHP version disclosure.", "PHP version disclosure.", "/index.php"},
		{"No leading slash: whole message.", "No leading slash: whole message.", ""},
		{"/path/without/colon", "/path/without/colon", ""},
	}
	for _, tc := range cases {
		msg, uri := splitURIPrefix(tc.in)
		if msg != tc.msg || uri != tc.uri {
			t.Errorf("splitURIPrefix(%q) = (%q, %q), want (%q, %q)", tc.in, msg, uri, tc.msg, tc.uri)
		}
	}
}

// TestSplitReferences_TrailingPeriod pins the grammar fix nikto itself applies
// (add_vulnerability appends "." when the message lacks one).
func TestSplitReferences_TrailingPeriod(t *testing.T) {
	msg, refs := splitReferences("Issue text. See: CVE-2000-0709")
	if msg != "Issue text." {
		t.Errorf("message = %q", msg)
	}
	if len(refs) != 1 || refs[0] != "CVE-2000-0709" {
		t.Errorf("refs = %v", refs)
	}
}

func TestIsConnectFailure(t *testing.T) {
	if !isConnectFailure("FAIL", "anything") {
		t.Error("FAIL pseudo-id must be a connect failure")
	}
	if !isConnectFailure("000000", "Unable to connect to example.com:443") {
		t.Error("'Unable to connect' must be a connect failure")
	}
	if isConnectFailure("000024", "Attackers may crash FrontPage.") {
		t.Error("a real result must not be classified as a connect failure")
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
