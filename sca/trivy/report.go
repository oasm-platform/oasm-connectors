package main

import (
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// report is a Trivy JSON report (`--format json`, SchemaVersion 2). Only the
// fields the adapter maps are declared.
type report struct {
	Results []result `json:"Results"`
}

// result is one scanned target: a lockfile, an IaC file or a file holding
// secrets. Target is relative to the scanned directory.
type result struct {
	Target            string             `json:"Target"`
	Class             string             `json:"Class"`
	Type              string             `json:"Type"`
	Packages          []pkg              `json:"Packages"`
	Vulnerabilities   []vulnerability    `json:"Vulnerabilities"`
	Misconfigurations []misconfiguration `json:"Misconfigurations"`
	Secrets           []secret           `json:"Secrets"`
}

type pkgIdentifier struct {
	UID string `json:"UID"`
}

// pkg is a detected package; Locations are its lines in the Target.
type pkg struct {
	ID         string        `json:"ID"`
	Identifier pkgIdentifier `json:"Identifier"`
	Locations  []struct {
		StartLine int32 `json:"StartLine"`
		EndLine   int32 `json:"EndLine"`
	} `json:"Locations"`
}

type cvss struct {
	V2Score   float64 `json:"V2Score"`
	V2Vector  string  `json:"V2Vector"`
	V3Score   float64 `json:"V3Score"`
	V3Vector  string  `json:"V3Vector"`
	V40Score  float64 `json:"V40Score"`
	V40Vector string  `json:"V40Vector"`
}

type vulnerability struct {
	VulnerabilityID  string          `json:"VulnerabilityID"`
	PkgID            string          `json:"PkgID"`
	PkgName          string          `json:"PkgName"`
	PkgPath          string          `json:"PkgPath"`
	PkgIdentifier    pkgIdentifier   `json:"PkgIdentifier"`
	InstalledVersion string          `json:"InstalledVersion"`
	FixedVersion     string          `json:"FixedVersion"`
	SeveritySource   string          `json:"SeveritySource"`
	PrimaryURL       string          `json:"PrimaryURL"`
	Title            string          `json:"Title"`
	Description      string          `json:"Description"`
	Severity         string          `json:"Severity"`
	CweIDs           []string        `json:"CweIDs"`
	CVSS             map[string]cvss `json:"CVSS"`
	References       []string        `json:"References"`
	PublishedDate    *time.Time      `json:"PublishedDate"`
	LastModifiedDate *time.Time      `json:"LastModifiedDate"`
}

type misconfiguration struct {
	Type          string   `json:"Type"`
	ID            string   `json:"ID"`
	Title         string   `json:"Title"`
	Description   string   `json:"Description"`
	Message       string   `json:"Message"`
	Resolution    string   `json:"Resolution"`
	Severity      string   `json:"Severity"`
	PrimaryURL    string   `json:"PrimaryURL"`
	References    []string `json:"References"`
	Status        string   `json:"Status"`
	CauseMetadata struct {
		StartLine int32 `json:"StartLine"`
		EndLine   int32 `json:"EndLine"`
	} `json:"CauseMetadata"`
}

// secret is one detected secret. `Match` and `Code` are absent on purpose:
// Trivy masks the value there, but the line still carries its surroundings
// and must never be read, let alone forwarded.
type secret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int32  `json:"StartLine"`
	EndLine   int32  `json:"EndLine"`
}

// parseReport decodes a Trivy JSON report into findings. An empty file means
// nothing was found. `commit` is the scanned commit.
func parseReport(data []byte, commit string) ([]connector.Finding, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var r report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("trivy: invalid JSON report: %w", err)
	}

	var findings []connector.Finding
	for _, res := range r.Results {
		target := cleanTarget(res.Target)
		locations := packageLocations(res.Packages)
		for _, v := range res.Vulnerabilities {
			findings = append(findings, vulnFinding(v, res, target, locations, commit))
		}
		for _, m := range res.Misconfigurations {
			// The JSON report holds failures only unless
			// --include-non-failures is set; guard anyway.
			if m.Status != "" && m.Status != "FAIL" {
				continue
			}
			findings = append(findings, misconfigFinding(m, res, target, commit))
		}
		for _, s := range res.Secrets {
			findings = append(findings, secretFinding(s, target, commit))
		}
	}
	return findings, nil
}

// severityFor collapses Trivy's scale onto the platform enum. UNKNOWN (no
// vendor rated it yet) and anything unexpected become info.
func severityFor(trivy string) string {
	switch strings.ToUpper(trivy) {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MEDIUM":
		return "medium"
	case "LOW":
		return "low"
	default:
		return "info"
	}
}

func vulnFinding(v vulnerability, res result, target string, locations map[string][2]int32, commit string) connector.Finding {
	file := target
	if v.PkgPath != "" {
		// Packages inside archives (jars) name their own path.
		file = cleanTarget(v.PkgPath)
	}
	lines := locations[v.PkgIdentifier.UID]
	if lines == [2]int32{} {
		lines = locations[v.PkgID]
	}

	var cveIDs []string
	if strings.HasPrefix(v.VulnerabilityID, "CVE-") {
		cveIDs = []string{v.VulnerabilityID}
	}
	score, vector := pickCVSS(v.CVSS, v.SeveritySource)

	title := v.Title
	if title == "" {
		title = v.VulnerabilityID
	}
	description := strings.TrimSpace(v.Description)
	if description == "" {
		description = title
	} else if v.Title != "" {
		description = v.Title + ". " + description
	}
	description += fmt.Sprintf(" Package %s %s, declared in %s.", v.PkgName, v.InstalledVersion, file)

	// FixedVersion may list one fix per release line ("3.1.0, 2.1.3").
	solution := fmt.Sprintf("Upgrade %s to a fixed version (%s), then regenerate the lockfile.", v.PkgName, v.FixedVersion)
	if v.FixedVersion == "" {
		solution = fmt.Sprintf("No fixed version of %s is available yet. Remove or replace the dependency, or mitigate the affected functionality.", v.PkgName)
	}

	f := connector.Finding{
		Name:             fmt.Sprintf("%s in %s", v.VulnerabilityID, v.PkgName),
		Severity:         severityFor(v.Severity),
		Description:      description,
		Solution:         solution,
		Tags:             uniqueSorted([]string{"sca", "trivy", res.Type}),
		References:       uniqueSorted(append([]string{v.PrimaryURL}, v.References...)),
		CVEID:            cveIDs,
		CWEID:            uniqueSorted(v.CweIDs),
		CVSSScore:        score,
		CVSSMetrics:      vector,
		FilePath:         file,
		LineStart:        lines[0],
		LineEnd:          lines[1],
		Commit:           commit,
		PackageName:      v.PkgName,
		InstalledVersion: v.InstalledVersion,
		FixedVersion:     v.FixedVersion,
		// One advisory per installed package per file: a lockfile may pin
		// the same package at two versions, which stay two findings.
		Fingerprint: fmt.Sprintf("%s:%s:%s", v.VulnerabilityID, file, pkgKey(v)),
	}
	if v.PublishedDate != nil {
		f.PublicationDate = *v.PublishedDate
	}
	if v.LastModifiedDate != nil {
		f.ModificationDate = *v.LastModifiedDate
	}
	return f
}

func misconfigFinding(m misconfiguration, res result, target, commit string) connector.Finding {
	title := m.Title
	if title == "" {
		title = m.Message
	}
	description := strings.TrimSpace(m.Description)
	if m.Message != "" && m.Message != description {
		description = strings.TrimSpace(description + " " + m.Message)
	}
	location := target
	if m.CauseMetadata.StartLine > 0 {
		location = fmt.Sprintf("%s:%d", target, m.CauseMetadata.StartLine)
	}
	description += fmt.Sprintf(" Found in %s.", location)

	endLine := m.CauseMetadata.EndLine
	if endLine == 0 {
		endLine = m.CauseMetadata.StartLine
	}
	return connector.Finding{
		Name:        fmt.Sprintf("%s: %s", m.ID, title),
		Severity:    severityFor(m.Severity),
		Description: description,
		Solution:    m.Resolution,
		Tags:        uniqueSorted([]string{"misconfiguration", "iac", "trivy", res.Type}),
		References:  uniqueSorted(append([]string{m.PrimaryURL}, m.References...)),
		FilePath:    target,
		LineStart:   m.CauseMetadata.StartLine,
		LineEnd:     endLine,
		Commit:      commit,
		Fingerprint: fmt.Sprintf("%s:%s:%d", m.ID, target, m.CauseMetadata.StartLine),
	}
}

func secretFinding(s secret, target, commit string) connector.Finding {
	title := s.Title
	if title == "" {
		title = s.RuleID
	}
	location := target
	if s.StartLine > 0 {
		location = fmt.Sprintf("%s:%d", target, s.StartLine)
	}
	endLine := s.EndLine
	if endLine == 0 {
		endLine = s.StartLine
	}
	return connector.Finding{
		Name:        "Leaked secret: " + s.RuleID,
		Severity:    severityFor(s.Severity),
		Description: fmt.Sprintf("%s detected in %s. The value is redacted; rotate the credential, then remove it from the repository history.", title, location),
		Solution:    "Revoke and rotate the exposed credential first — removing it from the code does not invalidate it. Then purge it from history and load secrets from a secret manager or environment instead.",
		Tags:        uniqueSorted([]string{"secret", "trivy", strings.ToLower(s.Category)}),
		FilePath:    target,
		LineStart:   s.StartLine,
		LineEnd:     endLine,
		Commit:      commit,
		Fingerprint: fmt.Sprintf("%s:%s:%d", s.RuleID, target, s.StartLine),
	}
}

// packageLocations indexes each package's first location by UID and by ID,
// so a vulnerability can point at the lockfile line declaring its package.
func packageLocations(pkgs []pkg) map[string][2]int32 {
	locations := make(map[string][2]int32, len(pkgs))
	for _, p := range pkgs {
		if len(p.Locations) == 0 {
			continue
		}
		loc := [2]int32{p.Locations[0].StartLine, p.Locations[0].EndLine}
		if loc[1] == 0 {
			loc[1] = loc[0]
		}
		if p.Identifier.UID != "" {
			locations[p.Identifier.UID] = loc
		}
		if p.ID != "" {
			locations[p.ID] = loc
		}
	}
	return locations
}

func pkgKey(v vulnerability) string {
	if v.PkgID != "" {
		return v.PkgID
	}
	return v.PkgName + "@" + v.InstalledVersion
}

// cvssSourcePreference orders the CVSS sources tried after the one Trivy
// took the severity from.
var cvssSourcePreference = []string{"nvd", "ghsa", "redhat"}

// pickCVSS returns one score and vector: from the severity's own source when
// it has one, else NVD, GHSA, Red Hat, then any other source alphabetically.
// Within a source, CVSS v3 wins over v4.0 and v2.
func pickCVSS(scores map[string]cvss, severitySource string) (float64, string) {
	if len(scores) == 0 {
		return 0, ""
	}
	order := append([]string{severitySource}, cvssSourcePreference...)
	rest := make([]string, 0, len(scores))
	for source := range scores {
		rest = append(rest, source)
	}
	sort.Strings(rest)
	for _, source := range append(order, rest...) {
		c, ok := scores[source]
		if !ok {
			continue
		}
		switch {
		case c.V3Score > 0:
			return c.V3Score, c.V3Vector
		case c.V40Score > 0:
			return c.V40Score, c.V40Vector
		case c.V2Score > 0:
			return c.V2Score, c.V2Vector
		}
	}
	return 0, ""
}

// cleanTarget turns a reported target into a forward-slash path relative to
// the repository root. `trivy fs <dir>` already reports relative targets.
func cleanTarget(target string) string {
	cleaned := path.Clean(strings.ReplaceAll(target, "\\", "/"))
	return strings.TrimPrefix(cleaned, "./")
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
