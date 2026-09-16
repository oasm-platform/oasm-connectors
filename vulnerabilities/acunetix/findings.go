package main

import (
	"context"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// detailWorkers bounds how many per-vulnerability detail lookups run at once.
// The semaphore is acquired in the parent loop (never one goroutine per item),
// so this is a true ceiling on in-flight HTTP detail requests.
const detailWorkers = 8

// cveRe and cweRe pull identifiers out of Acunetix tags and reference hrefs.
var (
	cveRe = regexp.MustCompile(`(?i)CVE-\d{4}-\d+`)
	cweRe = regexp.MustCompile(`(?i)CWE-\d+`)
)

// severityRank orders findings for the deterministic emit sort.
var severityRank = map[string]int{
	"info":     0,
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// mapSeverity converts the Acunetix 0..4 severity legend (doc:6838-6845) to the
// connector severity enum. Anything out of range maps to info so a future/odd
// severity can never fail Finding.Validate and abort the whole stream.
func mapSeverity(severity int) string {
	switch severity {
	case 0:
		return "info"
	case 1:
		return "low"
	case 2:
		return "medium"
	case 3:
		return "high"
	case 4:
		return "critical"
	default:
		return "info"
	}
}

// extractIDs scans every source string for CVE/CWE identifiers, upper-cases the
// matches and de-duplicates them preserving first-seen order.
func extractIDs(sources []string) (cves, cwes []string) {
	cveSeen := map[string]bool{}
	cweSeen := map[string]bool{}
	for _, s := range sources {
		for _, m := range cveRe.FindAllString(s, -1) {
			u := strings.ToUpper(m)
			if !cveSeen[u] {
				cveSeen[u] = true
				cves = append(cves, u)
			}
		}
		for _, m := range cweRe.FindAllString(s, -1) {
			u := strings.ToUpper(m)
			if !cweSeen[u] {
				cweSeen[u] = true
				cwes = append(cwes, u)
			}
		}
	}
	return cves, cwes
}

// parseTimestamp parses the timestamp formats Acunetix uses, falling back to the
// current UTC time so a finding always carries a usable timestamp.
func parseTimestamp(raw string) time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02", "2006-01-02T15:04:05"} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts
		}
	}
	return time.Now().UTC()
}

// hostFromURL returns the host of raw, or fallback when raw has no host.
func hostFromURL(raw, fallback string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err == nil && u.Hostname() != "" {
		return u.Hostname()
	}
	return fallback
}

// mapVulnerability maps a list-item vulnerability to a finding. It returns
// false when vt_name is blank so no empty-name finding is ever emitted (that
// would abort the whole stream). References are unavailable on list items, so
// CVE/CWE come from tags only.
func mapVulnerability(v vulnerability, target string) (connector.Finding, bool) {
	if strings.TrimSpace(v.VTName) == "" {
		return connector.Finding{}, false
	}

	tags := append([]string(nil), v.Tags...)
	if v.Status != "" {
		tags = append(tags, "status:"+v.Status)
	}
	cves, cwes := extractIDs(v.Tags)

	return connector.Finding{
		Name:      v.VTName,
		Severity:  mapSeverity(v.Severity),
		Tags:      tags,
		CVEID:     cves,
		CWEID:     cwes,
		MatchedAt: v.AffectsURL,
		Host:      hostFromURL(v.AffectsURL, target),
		Timestamp: parseTimestamp(v.LastSeen),
	}, true
}

// mapVulnerabilityDetails maps a detail response to a finding: it starts from
// the list-item mapping, then overlays recommendation, CVSS score/vector and
// references. CVE/CWE are re-extracted from tags plus reference hrefs.
func mapVulnerabilityDetails(d vulnerabilityDetails, target string) (connector.Finding, bool) {
	f, ok := mapVulnerability(d.vulnerability, target)
	if !ok {
		return connector.Finding{}, false
	}

	f.Solution = d.Recommendation

	// cis: prefer the CVSS 4.0 score, then the highest-version cvss_score.
	if d.CVSS4Score > 0 {
		f.CVSSScore = d.CVSS4Score
	} else {
		f.CVSSScore = d.CVSSScore
	}
	switch {
	case d.CVSS4 != "":
		f.CVSSMetrics = d.CVSS4
	case d.CVSS3 != "":
		f.CVSSMetrics = d.CVSS3
	case d.CVSS2 != "":
		f.CVSSMetrics = d.CVSS2
	}

	refs := make([]string, 0, len(d.References))
	sources := make([]string, 0, len(d.Tags)+len(d.References))
	sources = append(sources, d.Tags...)
	for _, l := range d.References {
		sources = append(sources, l.Href)
		if strings.TrimSpace(l.Href) != "" {
			refs = append(refs, l.Href)
		}
	}
	if len(refs) > 0 {
		f.References = refs
	}

	f.CVEID, f.CWEID = extractIDs(sources)
	return f, true
}

// dedupeVulnerabilities keeps the first occurrence of each vuln_id+affects_url
// pair, preserving input order. Pagination can over-fetch by one page, so this
// is the safety net against duplicate findings.
func dedupeVulnerabilities(items []vulnerability) []vulnerability {
	seen := make(map[string]bool, len(items))
	out := make([]vulnerability, 0, len(items))
	for _, v := range items {
		key := v.VulnID + "\x00" + v.AffectsURL
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, v)
	}
	return out
}

// collectFindings lists a scan result's vulnerabilities, enriches each with a
// bounded-pool detail fetch (falling back to list-item data when a detail call
// fails — a vulnerability is never dropped), deterministically sorts them and
// streams them on out.
//
// ponytail: all findings are held in memory so they can be sorted; fine for the
// connector's expected volumes. Upgrade path: stream with an external sort if
// scans ever return tens of thousands of items.
func collectFindings(ctx context.Context, client *acunetixClient, scanID, resultID, target string, out chan<- connector.Finding) error {
	items, err := client.listVulnerabilities(ctx, scanID, resultID)
	if err != nil {
		return err
	}

	items = dedupeVulnerabilities(items)
	if len(items) == 0 {
		log.Printf("acunetix: no vulnerabilities")
		return nil
	}

	type pair struct {
		vulnID  string
		finding connector.Finding
		ok      bool
	}

	results := make([]pair, len(items))
	sem := make(chan struct{}, detailWorkers)
	var wg sync.WaitGroup
	// Join in-flight workers even when an early-cancellation return skips the
	// explicit Wait below, so no goroutine writes results after we return.
	defer wg.Wait()

	for i, item := range items {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}

		wg.Add(1)
		go func(i int, item vulnerability) {
			defer wg.Done()
			defer func() { <-sem }()

			d, derr := client.getVulnerability(ctx, scanID, resultID, item.VulnID)
			if derr != nil {
				log.Printf("acunetix: vuln %s detail: %v", item.VulnID, derr)
				f, ok := mapVulnerability(item, target)
				results[i] = pair{vulnID: item.VulnID, finding: f, ok: ok}
				return
			}
			f, ok := mapVulnerabilityDetails(*d, target)
			results[i] = pair{vulnID: item.VulnID, finding: f, ok: ok}
		}(i, item)
	}

	wg.Wait()

	pairs := make([]pair, 0, len(results))
	skipped := 0
	for _, r := range results {
		if !r.ok {
			skipped++
			continue
		}
		pairs = append(pairs, r)
	}

	// The ONLY sort: severity desc, then vuln_id asc, then matched-at asc.
	// SliceStable + the tertiary key makes the emit order fully deterministic
	// even for two rows sharing vuln_id and severity.
	sort.SliceStable(pairs, func(i, j int) bool {
		ri, rj := severityRank[pairs[i].finding.Severity], severityRank[pairs[j].finding.Severity]
		if ri != rj {
			return ri > rj
		}
		if pairs[i].vulnID != pairs[j].vulnID {
			return pairs[i].vulnID < pairs[j].vulnID
		}
		return pairs[i].finding.MatchedAt < pairs[j].finding.MatchedAt
	})

	emitted := 0
	for _, p := range pairs {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- p.finding:
			emitted++
		}
	}

	log.Printf("acunetix: done findings=%d skipped=%d", emitted, skipped)
	return nil
}
