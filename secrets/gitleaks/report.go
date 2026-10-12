package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// leak is one entry of a gitleaks JSON report (`--report-format json`). Only
// the fields the adapter maps are declared; `Secret` and `Match` are absent on
// purpose — the scan runs with --redact and the value must never be read,
// let alone forwarded.
type leak struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int32    `json:"StartLine"`
	EndLine     int32    `json:"EndLine"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Tags        []string `json:"Tags"`
}

// parseReport decodes a gitleaks JSON report. An empty file means no leaks.
func parseReport(data []byte) ([]leak, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var leaks []leak
	if err := json.Unmarshal(data, &leaks); err != nil {
		return nil, fmt.Errorf("gitleaks: invalid JSON report: %w", err)
	}
	return leaks, nil
}

// criticalRules are secrets that grant broad, long-lived access on their own
// (private keys, cloud root credentials). Every other leak is high: a
// committed credential is always actionable.
var criticalRules = map[string]bool{
	"private-key":             true,
	"aws-access-token":        true,
	"gcp-service-account":     true,
	"azure-ad-client-secret":  true,
	"github-app-token":        true,
	"github-pat":              true,
	"github-fine-grained-pat": true,
	"gitlab-pat":              true,
}

func severityFor(ruleID string) string {
	if criticalRules[ruleID] {
		return "critical"
	}
	return "high"
}

// toFinding maps one leak onto a Finding. `checkoutDir` is stripped from the
// file path so findings point at repository-relative paths; `commit` is the
// scanned commit, used when the leak itself carries none (tree scans).
func toFinding(l leak, checkoutDir, commit string) connector.Finding {
	file := relativePath(l.File, checkoutDir)
	leakCommit := l.Commit
	if leakCommit == "" {
		leakCommit = commit
	}
	endLine := l.EndLine
	if endLine == 0 {
		endLine = l.StartLine
	}

	description := l.Description
	if description == "" {
		description = "A secret was detected in the repository."
	}
	location := file
	if l.StartLine > 0 {
		location = fmt.Sprintf("%s:%d", file, l.StartLine)
	}

	return connector.Finding{
		Name:        "Leaked secret: " + l.RuleID,
		Severity:    severityFor(l.RuleID),
		Description: fmt.Sprintf("%s Found in %s. The value is redacted; rotate the credential, then remove it from the repository history.", description, location),
		Solution:    "Revoke and rotate the exposed credential first — removing it from the code does not invalidate it. Then purge it from history and load secrets from a secret manager or environment instead.",
		Tags:        uniqueSorted(append([]string{"secret", "gitleaks"}, l.Tags...)),
		FilePath:    file,
		LineStart:   l.StartLine,
		LineEnd:     endLine,
		Commit:      leakCommit,
		// Stable across scans while the secret stays put: same rule, same
		// file, same line. The platform deduplicates on it.
		Fingerprint: fmt.Sprintf("%s:%s:%d", l.RuleID, file, l.StartLine),
	}
}

// relativePath turns a reported path into a forward-slash path relative to
// the checkout root. gitleaks reports tree-scan paths prefixed with the
// scanned directory; history-scan paths are already repository-relative.
func relativePath(file, root string) string {
	cleaned := filepath.Clean(file)
	if root != "" {
		if rel, err := filepath.Rel(filepath.Clean(root), cleaned); err == nil && !strings.HasPrefix(rel, "..") {
			cleaned = rel
		}
	}
	return filepath.ToSlash(cleaned)
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
