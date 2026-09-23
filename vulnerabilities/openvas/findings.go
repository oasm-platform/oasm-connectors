package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// resultsBackoff is the pause between get_results re-fetch attempts inside the
// truncation policy. A package variable (like T6's pollInterval) so tests can
// shrink it.
var resultsBackoff = 2 * time.Second

// maxResultRefetches bounds the re-fetch attempts when get_results reports
// more results than it delivered (a task reaching Done does not guarantee
// gvmd has materialized every result for GMP yet).
const maxResultRefetches = 3

// mapSeverity maps a numeric OpenVAS severity (GMP <severity>, 0.0–10.0) onto
// the closed connector severity enum. The legacy <threat> string is ignored.
// Anything outside [0,10] must land on info via default — an out-of-enum value
// fails Finding.Validate and aborts the whole stream. Negatives match the
// first case (score < 0.1), so default only catches > 10.0; NaN matches no
// case and also falls to default.
func mapSeverity(score float64) string {
	switch {
	case score < 0.1: // 0.0 (and sub-0.1 dust / negatives) → info
		return "info"
	case score < 4.0: // 0.1–3.9 → low
		return "low"
	case score < 7.0: // 4.0–6.9 → medium
		return "medium"
	case score < 9.0: // 7.0–8.9 → high
		return "high"
	case score <= 10.0: // 9.0–10.0 → critical
		return "critical"
	default: // outside [0,10] → info, never an out-of-enum value
		return "info"
	}
}

// finding is the internal mapped form of one GMP result; toSDKFinding converts
// it to the canonical connector.Finding streamed on the wire.
type finding struct {
	name             string
	severity         string
	description      string
	solution         string
	host             string
	ip               string
	matchedAt        string
	ports            []string
	cveID            []string
	cweID            []string
	references       []string
	cvssScore        float64
	cvssMetrics      string
	confidence       float64
	timestamp        time.Time
	modificationDate time.Time
}

// hostOf returns the result's display host: the <hostname> DIRECT child of
// <host> when present, else the <host> chardata (usually an IP), trimmed.
func hostOf(r Result) string {
	if h := strings.TrimSpace(r.Host.Hostname); h != "" {
		return h
	}
	return strings.TrimSpace(r.Host.IP)
}

// mapResult maps one GMP <result> to the internal finding. Name falls back
// result → nvt/name → nvt@oid → "OpenVAS result" so it is never empty (an
// empty name fails Validate and aborts the stream).
func mapResult(r Result) finding {
	port := strings.TrimSpace(r.Port)
	host := hostOf(r)

	name := strings.TrimSpace(r.Name)
	if name == "" {
		name = strings.TrimSpace(r.Nvt.Name)
	}
	if name == "" {
		name = strings.TrimSpace(r.Nvt.OID)
	}
	if name == "" {
		name = "OpenVAS result"
	}

	// Host chardata is the IP only when it parses as an IP literal.
	ipChardata := strings.TrimSpace(r.Host.IP)
	var ip string
	if net.ParseIP(ipChardata) != nil {
		ip = ipChardata
	}

	matchedAt := host
	if port != "" {
		matchedAt = host + ":" + port
	}
	var ports []string
	if port != "" {
		ports = []string{port}
	}

	var cveID, cweID, references []string
	for _, ref := range r.Nvt.Refs.Ref {
		id := strings.TrimSpace(ref.ID)
		if id == "" {
			continue
		}
		switch ref.Type {
		case "cve":
			cveID = append(cveID, id)
		case "cwe":
			cweID = append(cweID, id)
		case "url":
			references = append(references, id)
		}
	}

	// CVSS: the nvt severity entry (cvss_base / cvss_base_v2) wins when its
	// score parses; otherwise the result's numeric severity stands. The entry's
	// <value> vector is the metrics string when non-empty.
	cvssScore := r.Severity
	var cvssMetrics string
	for _, sev := range r.Nvt.Severities.Severity {
		if sev.Type != "cvss_base" && sev.Type != "cvss_base_v2" {
			continue
		}
		if s, err := strconv.ParseFloat(strings.TrimSpace(sev.Score), 64); err == nil {
			cvssScore = s
		}
		cvssMetrics = strings.TrimSpace(sev.Value)
		break // the first cvss-typed entry owns score + vector
	}

	return finding{
		name:             name,
		severity:         mapSeverity(r.Severity),
		description:      r.Description,
		solution:         r.Nvt.Solution,
		host:             host,
		ip:               ip,
		matchedAt:        matchedAt,
		ports:            ports,
		cveID:            cveID,
		cweID:            cweID,
		references:       references,
		cvssScore:        cvssScore,
		cvssMetrics:      cvssMetrics,
		confidence:       float64(r.QOD.Value),
		timestamp:        parseResultTime(r.CreationTime),
		modificationDate: parseResultTime(r.ModificationTime),
	}
}

// parseResultTime parses a GMP iso_time (RFC3339, or the zone-less
// YYYY-MM-DDThh:mm:ssZ spelling) into UTC. Unparseable input yields the zero
// time, which the wire omits rather than shipping bogus epoch time.
func parseResultTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z"} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

// toSDKFinding converts the internal finding to the canonical SDK Finding.
func (f finding) toSDKFinding() connector.Finding {
	return connector.Finding{
		Name:             f.name,
		Severity:         f.severity,
		Description:      f.description,
		Solution:         f.solution,
		Host:             f.host,
		IP:               f.ip,
		MatchedAt:        f.matchedAt,
		Ports:            f.ports,
		CVEID:            f.cveID,
		CWEID:            f.cweID,
		References:       f.references,
		CVSSScore:        f.cvssScore,
		CVSSMetrics:      f.cvssMetrics,
		Confidence:       f.confidence,
		Timestamp:        f.timestamp,
		ModificationDate: f.modificationDate,
	}
}

// mapResults maps every result to a connector.Finding in deterministic emit
// order: sort.SliceStable by (host, port, nvt oid, id). The id tiebreaker
// makes the sort key total, so rows sharing host/port/oid cannot reorder
// between runs — shuffled input yields byte-identical output order.
func mapResults(results []Result) []connector.Finding {
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i], results[j]
		if ha, hb := hostOf(a), hostOf(b); ha != hb {
			return ha < hb
		}
		if pa, pb := strings.TrimSpace(a.Port), strings.TrimSpace(b.Port); pa != pb {
			return pa < pb
		}
		if a.Nvt.OID != b.Nvt.OID {
			return a.Nvt.OID < b.Nvt.OID
		}
		return a.ID < b.ID
	})
	out := make([]connector.Finding, 0, len(results))
	for _, r := range results {
		out = append(out, mapResult(r).toSDKFinding())
	}
	return out
}

// sleepOrCancel waits for d, returning the T3-style cancelled error when ctx
// fires first so a backoff sleep is cancel-unblockable.
func sleepOrCancel(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("retryable: openvas: cancelled: %w", ctx.Err())
	case <-t.C:
		return nil
	}
}

// fetchResults is collectFindings' truncation policy — the SINGLE owner
// (GetResults reports counts but enforces nothing). fetch performs one
// GetResults call returning (results, reported, countPresent, err).
//
// Policy:
//   - countPresent && short: re-fetch up to maxResultRefetches times with
//     resultsBackoff between attempts (each sleep cancel-aware); still short
//     after the bounded retries → retryable: openvas: results truncated
//     (got N of M). Never silently stream a partial set.
//   - countPresent == false: no reported count exists to compare against, so
//     retry ONCE for settle time, then ACCEPT the fetched set — that single
//     settle re-fetch is the whole rule, never more.
//   - any fetch error is returned unchanged (already prefixed by T3/T4).
func fetchResults(ctx context.Context, fetch func(context.Context) ([]Result, int, bool, error)) ([]Result, error) {
	results, reported, countPresent, err := fetch(ctx)
	if err != nil {
		return nil, err
	}

	if !countPresent {
		if err := sleepOrCancel(ctx, resultsBackoff); err != nil {
			return nil, err
		}
		results, _, _, err = fetch(ctx)
		if err != nil {
			return nil, err
		}
		return results, nil
	}

	for i := 0; i < maxResultRefetches && len(results) < reported; i++ {
		if err := sleepOrCancel(ctx, resultsBackoff); err != nil {
			return nil, err
		}
		next, rep, ok, ferr := fetch(ctx)
		if ferr != nil {
			return nil, ferr
		}
		results = next
		if ok {
			reported = rep
		}
	}
	if len(results) < reported {
		return nil, fmt.Errorf("retryable: openvas: results truncated (got %d of %d)", len(results), reported)
	}
	return results, nil
}

// collectFindings fetches the task's results (fetchResults owns the
// truncation policy), maps them to findings in deterministic order, and
// streams them on out. An unparseable response surfaces as the GetResults
// error (never silently dropped); target is part of the signature T6 calls —
// host derives from each result, so it is unused here.
func collectFindings(ctx context.Context, c *gmpConn, taskID string, target string, out chan<- connector.Finding) error {
	results, err := fetchResults(ctx, func(ctx context.Context) ([]Result, int, bool, error) {
		return c.GetResults(ctx, taskID)
	})
	if err != nil {
		return err
	}
	for _, f := range mapResults(results) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case out <- f:
		}
	}
	return nil
}
