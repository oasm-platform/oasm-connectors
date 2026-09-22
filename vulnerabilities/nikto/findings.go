package main

import (
	"net/url"
	"regexp"
)

// --- Severity rubric ---
//
// Nikto reports no severity: neither its stdout nor its JSON report carries a
// CVSS score or a risk band. Every nikto result is therefore classified by the
// wording of its db_tests message, using the same ordered keyword rubric the
// WPScan connector applies to its unscored titles (first match wins,
// critical -> info). Findings that match nothing default to "medium" and are
// labelled so the heuristic is auditable after the fact.
var severityRules = []struct {
	severity string
	re       *regexp.Regexp
}{
	{"critical", regexp.MustCompile(`(?i)\b(?:remote code execution|arbitrary code execution|code execution|command execution|command injection|os command|shell|backdoor|remote file inclusions?|rfi)\b`)},
	{"high", regexp.MustCompile(`(?i)\b(?:sql injection|sqli|blind sql|xpath injection|ldap injection|xml external entity|xxe|ssrf|server[- ]side request forgery|local file inclusions?|lfi|directory traversal|path traversal|file inclusions?|arbitrary file|authentication bypass|auth bypass|privilege escalation|privesc|default (?:password|credential)|weak password|admin password|upload|deserialization|object injection)\b`)},
	{"medium", regexp.MustCompile(`(?i)\b(?:cross[- ]site scripting|xss|csrf|cross[- ]site request forgery|information disclosure|sensitive (?:data|information)|disclos|phpinfo|full path|physical path|directory (?:listing|indexing)|index of /|idor|access control|header .*missing|missing .*header| header .* not set|http trace|trace method|put method|delete method|webdav|source code|backup file|\.git|configuration file|debug)\b`)},
	{"low", regexp.MustCompile(`(?i)\b(?:redirect|redirection|clickjacking|x-frame-options|content-security-policy|cookie|httponly|secure flag|autocomplete|robots\.txt|sitemap|etag|inode|version|banner|outdated|deprecated|uncommon header)\b`)},
}

// titleFromMessage reduces a nikto message to a short title.
//
// Nikto has one text field per check and it is a full sentence written as a
// description ("The X-Content-Type-Options header is not set. This could allow
// the user agent to render the content..."). Dropped whole into Finding.Name it
// makes every vulnerability row a paragraph and leaves Description empty.
//
// The first sentence is the finding ("... is not set"); what follows is its
// consequence ("This could allow ..."). 575 of 7142 db_tests messages have that
// second sentence and get a genuinely shorter title; the remaining 92% are
// single-sentence and pass through unchanged, so a title is never invented.
//
// The split requires ". " followed by a capital so that "version 1.2.3 implies"
// and "admin/phplist" survive intact.
func titleFromMessage(message string) string {
	if loc := titleSplitRe.FindStringIndex(message); loc != nil {
		return message[:loc[0]+1]
	}
	return message
}

// titleSplitRe matches the sentence break: a period, whitespace, then a capital.
var titleSplitRe = regexp.MustCompile(`\.\s+[A-Z]`)

// cveRe matches a CVE token anywhere in a reference string. Matching anywhere
// (not a whole-token equality) matters because nikto has two reference shapes:
// the raw db_tests field holds bare tokens ("CVE-2000-0709"), while stdout
// carries the expanded advisory URL
// ("https://nvd.nist.gov/vuln/detail/CVE-2000-0709") — and the URL form is what
// a scan actually produces. Word boundaries keep a longer identifier from
// matching partially.
var cveRe = regexp.MustCompile(`\bCVE-\d{4}-\d{4,}\b`)

// cvesIn extracts every distinct CVE id from a set of reference strings.
func cvesIn(refs []string) []string {
	var out []string
	for _, ref := range refs {
		out = append(out, cveRe.FindAllString(ref, -1)...)
	}
	return dedupe(out)
}

// dedupe removes duplicates while preserving first-seen order.
func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// resolveSeverityFromMessage classifies a message by keyword, returning the
// band and its source: "" when a rule matched, "keyword-fallback" when the
// conservative default applied. This is the fallback path for check ids that
// are absent from db_tests (see resolveSeverity in adapter.go for the primary,
// database-grounded path).
func resolveSeverityFromMessage(message string) (severity, source string) {
	for _, rule := range severityRules {
		if rule.re.MatchString(message) {
			return rule.severity, ""
		}
	}
	return "medium", "keyword-fallback"
}

// hostFromTarget is the fallback Host when the item carries no host of its own.
func hostFromTarget(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Host
	}
	return target
}

// limitedWriter buffers stderr, keeping at most `limit` bytes.
type limitedWriter struct {
	buf   []byte
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	if len(w.buf) > w.limit {
		w.buf = w.buf[len(w.buf)-w.limit:]
	}
	return len(p), nil
}
