package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// itemRe matches the one stdout shape that carries a result, e.g.
// "+ [000024] /_vti_bin/shtml.exe: Attackers may crash FrontPage. See: CVE-2000-0709".
// The id is the six-digit db_tests test id, or the literal "FAIL" for the
// target-level "failed to scan" pseudo-item (see isConnectFailure).
var itemRe = regexp.MustCompile(`^\+ \[([^\]]+)\]\s?(.*)$`)

// seeSplit separates the message body from the advisory list nikto appends
// when it prints an item (core add_vulnerability: `$message .= " See: " .
// expand_advisory_links($refs)`). The stored report keeps them apart, but
// stdout — the only channel a CLI gives us — does not.
const seeSplit = " See: "

// NiktoAdapter runs Nikto and streams normalised findings.
type NiktoAdapter struct{}

// Validate is intentionally a no-op: inputs are validated upstream by the
// worker node against the connector's inputsSchema.
func (a NiktoAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

// Execute runs `nikto -h <target> -config <generated> -nointeractive`, parses
// the "+ [id] message" result lines off stdout, and streams one Finding each.
//
// The generated config exists for non-interactivity: nikto.conf.default sets
// UPDATES=yes (prompts to submit unidentified banners) and leaves PROMPTS live,
// neither of which has a CLI flag — a container would block on the prompt until
// the job timeout. See niktoConfigFile.
//
// Exit-code semantics: nikto exits 0 for a completed scan (vulnerable or not)
// and 1 for a usage/config/database error. stdout is therefore the source of
// truth: a nonzero exit is fatal only when it also produced zero findings, so
// partial results still reach the caller.
func (a NiktoAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	raw, _ := inputs["target"].(string)
	target := normalizeTarget(raw)
	if target == "" {
		return fmt.Errorf("target required")
	}

	bin := os.Getenv("NIKTO_BIN")
	if bin == "" {
		bin = "nikto.pl"
	}

	cfg, err := loadNiktoConfig()
	if err != nil {
		return err
	}

	workDir, err := os.MkdirTemp("", "oasm-nikto-*")
	if err != nil {
		return fmt.Errorf("nikto: create work dir: %w", err)
	}
	// NIKTO_KEEP_WORKDIR=1 keeps the generated config and stdout on disk for
	// debugging a failed scan; otherwise the temp dir is always removed.
	defer func() {
		if os.Getenv("NIKTO_KEEP_WORKDIR") != "" {
			fmt.Fprintf(os.Stderr, "nikto: keeping work dir %s\n", workDir)
			return
		}
		_ = os.RemoveAll(workDir)
	}()

	configPath := filepath.Join(workDir, "nikto.conf")
	if err := os.WriteFile(configPath, []byte(niktoConfigFile), 0o600); err != nil {
		return fmt.Errorf("nikto: write config: %w", err)
	}

	var stderr limitedWriter
	stderr.limit = 2048

	cmd := exec.CommandContext(ctx, bin, buildNiktoArgs(target, cfg, configPath)...)
	cmd.Stderr = &stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("nikto: stdout pipe: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("nikto: start: %w", err)
	}

	emitted, scanErr := scanItems(ctx, stdout, target, out)

	waitErr := cmd.Wait()
	tail := strings.TrimSpace(string(stderr.buf))

	// The adapter imposes NO ceiling of its own: a nikto run is bounded only by
	// the caller's context (the Worker cancels it at the job's timeoutSeconds)
	// and by -maxtime when the operator sets one. Long scans are expected — a
	// full CGI sweep against a slow host legitimately runs for hours.
	//
	// Nothing here shortens a scan, so the only reason ctx is done is that the
	// caller gave up. Report that faithfully and let the caller decide what the
	// partial results are worth; findings already streamed stay delivered.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if scanErr != nil {
		return fmt.Errorf("nikto: reading output: %w", scanErr)
	}
	if waitErr != nil && emitted == 0 {
		if tail != "" {
			return fmt.Errorf("nikto: %w: %s", waitErr, tail)
		}
		return fmt.Errorf("nikto: %w", waitErr)
	}
	return nil
}

// scanItems reads nikto's stdout line by line, emitting one Finding per result
// line and returning how many were sent.
func scanItems(ctx context.Context, stdout io.Reader, target string, out chan<- connector.Finding) (int, error) {
	scanner := bufio.NewScanner(stdout)
	// Result lines carry a full advisory message plus reference URLs; 1 MiB is
	// far past anything db_tests produces but keeps a pathological line from
	// tripping bufio's 64 KiB default.
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	emitted := 0
	for scanner.Scan() {
		f, ok := parseItemLine(scanner.Text(), target)
		if !ok {
			continue
		}
		select {
		case <-ctx.Done():
			return emitted, ctx.Err()
		case out <- f:
			emitted++
		}
	}
	return emitted, scanner.Err()
}

// parseItemLine maps one stdout line onto a Finding. Lines that are not result
// items — the banner, "Target IP"/"Target Hostname" header lines, the trailing
// "N host(s) tested" summary — yield ok=false.
//
// The id is used to enrich the finding from nikto's own test database
// (see niktdb.go): its tuning category supplies a grounded severity band and a
// category tag, and its references field supplies bare CVE tokens that stdout
// no longer carries (stdout prints the expanded nvd.nist.gov URL instead).
func parseItemLine(line, target string) (connector.Finding, bool) {
	m := itemRe.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
	if m == nil {
		return connector.Finding{}, false
	}
	id := strings.TrimSpace(m[1])
	body := strings.TrimSpace(m[2])
	if body == "" {
		return connector.Finding{}, false
	}

	// A target-level connect failure is not a vulnerability: nikto reports it
	// through the same "+ [FAIL] msg" channel as a real finding.
	if isConnectFailure(id, body) {
		fmt.Fprintf(os.Stderr, "nikto: scan skipped (not fatal): %s (target: %s)\n", body, target)
		return connector.Finding{}, false
	}

	message, uri := splitURIPrefix(body)
	message, refs := splitReferences(message)
	if message == "" {
		return connector.Finding{}, false
	}

	matchedAt := target
	if uri != "" {
		matchedAt = resolveURL(target, uri)
	}

	severity, _, categories := resolveSeverity(id, message)

	f := connector.Finding{
		Name:        titleFromMessage(message),
		Description: message,
		Severity:    severity,
		MatchedAt:   matchedAt,
		Host:        hostFromTarget(target),
		Timestamp:   time.Now(),
	}
	// Tags carry the check class and nothing else: Core's summary report renders
	// tags[0] as the finding's category, so a scanner-internal tag (the nikto
	// test id, the severity provenance) landing there would be published as a
	// category. Those values have no field of their own on Finding, so they stay
	// out of the wire format; the id still drives enrichment above.
	for _, c := range categories {
		f.Tags = append(f.Tags, "category:"+c)
	}

	f.References = append(f.References, refs...)

	// db_tests is the authoritative reference source: stdout renders CVEs as
	// expanded advisory URLs, so enriching from the database is what recovers
	// the bare CVE token (and adds any reference stdout omitted).
	if e, ok := dbEntryFor(id); ok {
		f.References = append(f.References, strings.Fields(e.refs)...)
	}
	f.References = dedupe(f.References)
	f.CVEID = cvesIn(f.References)
	return f, true
}

// dbEntryFor looks up a test id, tolerating an absent database.
func dbEntryFor(id string) (dbEntry, bool) {
	db := loadNiktoDB()
	if db == nil || id == "" {
		return dbEntry{}, false
	}
	e, ok := db.entries[id]
	return e, ok
}

// resolveSeverity picks the finding's severity band. The test database's tuning
// classification is authoritative — it says what the check does, independent of
// how the sentence is worded. Only when the id is unknown (nikto's plugin-only
// ids, which are not in db_tests) does it fall back to message keywords.
func resolveSeverity(id, message string) (severity, kind string, categories []string) {
	if e, ok := dbEntryFor(id); ok {
		categories = categoriesOf(e.tuning)
		if sev, _, found := severityFromTuning(e.tuning); found {
			return sev, "tuning:" + e.tuning, categories
		}
	}
	sev, source := resolveSeverityFromMessage(message)
	if source == "" {
		source = "keyword"
	}
	return sev, source, categories
}

// splitURIPrefix separates the affected-path prefix nikto prepends to every
// item message. nikto_tests.plugin builds the message as
// "$mark->{'root'}$uri: $message", and its own JSON report plugin strips the
// identical prefix before storing the message and keeps the URI in its own
// field — so stdout cannot carry them apart and we redo the split here.
//
// The prefix is only treated as a URI when it starts with "/" (nikto always
// prefixes a path, e.g. "/_vti_bin/shtml.exe: Attackers may ..."). A message
// containing a colon but no leading slash stays whole.
func splitURIPrefix(body string) (message, uri string) {
	if !strings.HasPrefix(body, "/") {
		return body, ""
	}
	idx := strings.Index(body, ": ")
	if idx < 0 {
		return body, ""
	}
	return strings.TrimSpace(body[idx+2:]), strings.TrimSpace(body[:idx])
}

// resolveURL turns an item's path into the absolute URL the worker persists as
// affected_url. A path that is already absolute is returned untouched.
func resolveURL(target, uri string) string {
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		return uri
	}
	return strings.TrimRight(target, "/") + uri
}

// splitReferences separates the message from the " See: <refs>" suffix nikto
// appends at print time. Without a suffix the whole line is the message.
func splitReferences(body string) (message string, refs []string) {
	message = body
	if idx := strings.Index(body, seeSplit); idx >= 0 {
		message = strings.TrimSpace(body[:idx])
		for _, tok := range strings.Fields(body[idx+len(seeSplit):]) {
			refs = append(refs, strings.Trim(tok, ","))
		}
	}
	if message != "" && !strings.HasSuffix(message, ".") {
		message += "."
	}
	return message, refs
}

// isConnectFailure reports whether the item is nikto's "could not reach the
// target" pseudo-finding rather than a real result. Treating it as a finding
// would persist a phantom vulnerability for a host that was simply down.
func isConnectFailure(id, message string) bool {
	if strings.EqualFold(id, "FAIL") {
		return true
	}
	lower := strings.ToLower(message)
	return strings.Contains(lower, "unable to connect to") ||
		strings.Contains(lower, "no web server found on") ||
		strings.Contains(lower, "failed to scan")
}
