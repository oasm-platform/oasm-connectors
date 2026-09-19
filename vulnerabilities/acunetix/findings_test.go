package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

func TestMapSeverity(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "info"},
		{1, "low"},
		{2, "medium"},
		{3, "high"},
		{4, "critical"},
		{-1, "info"},
		{99, "info"},
	}
	for _, tc := range cases {
		if got := mapSeverity(tc.in); got != tc.want {
			t.Errorf("mapSeverity(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestMapVulnerabilityEmptyVTNameSkipped(t *testing.T) {
	for _, name := range []string{"", "   ", "\t\n"} {
		if f, ok := mapVulnerability(vulnerability{VTName: name, VulnID: "v1"}, "https://t"); ok {
			t.Errorf("vt_name %q must be skipped, got finding %+v", name, f)
		}
	}
}

func TestMapVulnerabilityStatusTagAndFields(t *testing.T) {
	v := vulnerability{
		VulnID:     "v1",
		VTName:     "SQL Injection",
		Severity:   3,
		Tags:       []string{"CVE-2021-1234", "cwe-89", "sqli"},
		AffectsURL: "https://example.com/login?id=1",
		LastSeen:   "2024-01-02T10:00:00Z",
		Status:     "fixed",
	}
	f, ok := mapVulnerability(v, "fallback.example")
	if !ok {
		t.Fatal("expected mapping to succeed")
	}
	if f.Name != "SQL Injection" {
		t.Errorf("Name = %q", f.Name)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Host != "example.com" {
		t.Errorf("Host = %q, want example.com", f.Host)
	}
	if f.MatchedAt != v.AffectsURL {
		t.Errorf("MatchedAt = %q", f.MatchedAt)
	}
	if got := strings.Join(f.Tags, ","); !strings.Contains(got, "status:fixed") {
		t.Errorf("Tags = %v, want status:fixed appended", f.Tags)
	}
	// CVE/CWE from tags only, uppercased, de-duplicated.
	if len(f.CVEID) != 1 || f.CVEID[0] != "CVE-2021-1234" {
		t.Errorf("CVEID = %v, want [CVE-2021-1234]", f.CVEID)
	}
	if len(f.CWEID) != 1 || f.CWEID[0] != "CWE-89" {
		t.Errorf("CWEID = %v, want [CWE-89]", f.CWEID)
	}
}

func TestHostFromURL(t *testing.T) {
	cases := []struct{ raw, fallback, want string }{
		{"https://example.com:8443/x", "fb", "example.com"},
		{"not a url\x00", "fb", "fb"},
		{"", "fb", "fb"},
	}
	for _, tc := range cases {
		if got := hostFromURL(tc.raw, tc.fallback); got != tc.want {
			t.Errorf("hostFromURL(%q,%q) = %q, want %q", tc.raw, tc.fallback, got, tc.want)
		}
	}
}

func TestExtractIDsCaseInsensitiveDedupe(t *testing.T) {
	cves, cwes := extractIDs([]string{
		"see CVE-2021-1234",
		"also cve-2021-1234",
		"https://nvd.nist.gov/vuln/detail/CVE-2022-9999",
		"CWE-89 and CWE-79",
	})
	if len(cves) != 2 || cves[0] != "CVE-2021-1234" || cves[1] != "CVE-2022-9999" {
		t.Errorf("cves = %v, want [CVE-2021-1234 CVE-2022-9999]", cves)
	}
	if len(cwes) != 2 || cwes[0] != "CWE-89" || cwes[1] != "CWE-79" {
		t.Errorf("cwes = %v, want [CWE-89 CWE-79]", cwes)
	}
}

func TestMapVulnerabilityDetails(t *testing.T) {
	d := vulnerabilityDetails{
		vulnerability: vulnerability{
			VulnID:     "v1",
			VTName:     "Broken Auth",
			Severity:   4,
			Confidence: 95,
			Tags:       []string{"cve-2020-0001"},
			AffectsURL: "https://example.com/admin",
			LastSeen:   "2024-03-04",
		},
		Description:     "short desc",
		LongDescription: "detailed desc",
		Recommendation:  "Patch it",
		CVSS2:           "AV:N/AC:L/Au:N/C:P/I:P/A:P",
		CVSS3:           "CVSS:3.1/AV:N",
		CVSS4:           "CVSS:4.0/AV:N",
		CVSSScore:       7.5,
		CVSS4Score:      9.1,
		References: []link{
			{Rel: "cve", Href: "https://nvd.nist.gov/vuln/detail/CVE-2020-0001"},
			{Rel: "ref", Href: ""},
			{Rel: "ref", Href: "https://example.com/advisory"},
		},
	}
	f, ok := mapVulnerabilityDetails(d, "fb")
	if !ok {
		t.Fatal("expected mapping to succeed")
	}
	if f.Solution != "Patch it" {
		t.Errorf("Solution = %q, want Patch it", f.Solution)
	}
	if f.Synopsis != "short desc" {
		t.Errorf("Synopsis = %q, want short desc", f.Synopsis)
	}
	if f.Description != "detailed desc" {
		t.Errorf("Description = %q, want detailed desc", f.Description)
	}
	if f.Confidence != 95 {
		t.Errorf("Confidence = %v, want 95", f.Confidence)
	}
	if f.CVSSScore != 9.1 {
		t.Errorf("CVSSScore = %v, want 9.1 (cvss4_score preferred)", f.CVSSScore)
	}
	if f.CVSSMetrics != "CVSS:4.0/AV:N" {
		t.Errorf("CVSSMetrics = %q, want the cvss4 vector", f.CVSSMetrics)
	}
	if len(f.References) != 2 || f.References[0] != "https://nvd.nist.gov/vuln/detail/CVE-2020-0001" || f.References[1] != "https://example.com/advisory" {
		t.Errorf("References = %v, want non-empty hrefs only", f.References)
	}
	if len(f.CVEID) != 1 || f.CVEID[0] != "CVE-2020-0001" {
		t.Errorf("CVEID = %v, want [CVE-2020-0001] from tags + hrefs", f.CVEID)
	}

	// cvss4_score absent/zero → fall back to cvss_score and cvss3 vector, then cvss2.
	t.Run("fallback to cvss_score and cvss3", func(t *testing.T) {
		d2 := d
		d2.CVSS4Score = 0
		d2.CVSS4 = ""
		f2, ok := mapVulnerabilityDetails(d2, "fb")
		if !ok {
			t.Fatal("expected mapping to succeed")
		}
		if f2.CVSSScore != 7.5 {
			t.Errorf("CVSSScore = %v, want 7.5", f2.CVSSScore)
		}
		if f2.CVSSMetrics != "CVSS:3.1/AV:N" {
			t.Errorf("CVSSMetrics = %q, want the cvss3 vector", f2.CVSSMetrics)
		}
	})

	t.Run("fallback to cvss2", func(t *testing.T) {
		d3 := d
		d3.CVSS4Score, d3.CVSS4, d3.CVSS3 = 0, "", ""
		f3, ok := mapVulnerabilityDetails(d3, "fb")
		if !ok {
			t.Fatal("expected mapping to succeed")
		}
		if f3.CVSSMetrics != "AV:N/AC:L/Au:N/C:P/I:P/A:P" {
			t.Errorf("CVSSMetrics = %q, want the cvss2 vector", f3.CVSSMetrics)
		}
	})

	t.Run("description falls back to short description without long description", func(t *testing.T) {
		d4 := d
		d4.LongDescription = ""
		f4, ok := mapVulnerabilityDetails(d4, "fb")
		if !ok {
			t.Fatal("expected mapping to succeed")
		}
		if f4.Description != "short desc" {
			t.Errorf("Description = %q, want short desc fallback", f4.Description)
		}
	})

	// Empty vt_name is still skipped on the detail path.
	empty := d
	empty.VTName = " "
	if _, ok := mapVulnerabilityDetails(empty, "fb"); ok {
		t.Error("empty vt_name on details must be skipped")
	}
}

func TestParseTimestamp(t *testing.T) {
	if got := parseTimestamp("2024-01-02"); got.IsZero() || got.Year() != 2024 || got.Month() != time.January || got.Day() != 2 {
		t.Errorf("parseTimestamp(2024-01-02) = %v", got)
	}
	want := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	if got := parseTimestamp("2024-05-06T07:08:09Z"); !got.Equal(want) {
		t.Errorf("parseTimestamp(RFC3339) = %v, want %v", got, want)
	}
	if got := parseTimestamp("2024-05-06T07:08:09"); !got.Equal(want) {
		t.Errorf("parseTimestamp(no-zone) = %v, want %v", got, want)
	}
	before := time.Now().Add(-time.Minute)
	garbage := parseTimestamp("not-a-timestamp")
	if garbage.IsZero() || garbage.Before(before) {
		t.Errorf("parseTimestamp(garbage) = %v, want a recent non-zero time", garbage)
	}
}

func TestDedupeVulnerabilities(t *testing.T) {
	items := []vulnerability{
		{VulnID: "a", AffectsURL: "https://x/1", VTName: "A"},
		{VulnID: "a", AffectsURL: "https://x/2", VTName: "A2"},
		{VulnID: "a", AffectsURL: "https://x/1", VTName: "A-dup"},
		{VulnID: "b", AffectsURL: "https://x/1", VTName: "B"},
		{VulnID: "a", AffectsURL: "https://x/2", VTName: "A2-dup"},
	}
	got := dedupeVulnerabilities(items)
	if len(got) != 3 {
		t.Fatalf("got %d items, want 3: %+v", len(got), got)
	}
	// First occurrences preserved in input order.
	if got[0].VTName != "A" || got[1].VTName != "A2" || got[2].VTName != "B" {
		t.Errorf("dedupe order = %q,%q,%q", got[0].VTName, got[1].VTName, got[2].VTName)
	}
}

// collectClient points a client at a fake Acunetix server. The handler owns all
// endpoints; tests never mock the client, they exercise the real HTTP path.
func collectClient(t *testing.T, h http.HandlerFunc) (*acunetixClient, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	c := &acunetixClient{baseURL: srv.URL + "/api/v1", apiKey: "k", hc: srv.Client()}
	return c, srv.Close
}

func vulnListJSON(items []vulnerability) []byte {
	b, _ := json.Marshal(vulnerabilityListResponse{
		Vulnerabilities: items,
		Pagination:      pagination{Cursors: []*string{nil, nil}},
	})
	return b
}

func TestCollectFindingsFallBackOnDetailError(t *testing.T) {
	items := []vulnerability{
		{VulnID: "v-low", VTName: "Low One", Severity: 1, AffectsURL: "https://example.com/a", LastSeen: "2024-01-02"},
		{VulnID: "v-crit", VTName: "Crit One", Severity: 4, AffectsURL: "https://example.com/b", LastSeen: "2024-02-03"},
		{VulnID: "v-med", VTName: "Med One", Severity: 2, AffectsURL: "https://example.com/c", LastSeen: "2024-03-04"},
	}

	client, closeSrv := collectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/vulnerabilities/") {
			// The middle item's detail lookup fails hard (500).
			if strings.HasSuffix(r.URL.Path, "/v-med") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"code":500,"reason":"detail boom"}`))
				return
			}
			id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
			base := items[0]
			for _, it := range items {
				if it.VulnID == id {
					base = it
				}
			}
			_ = json.NewEncoder(w).Encode(vulnerabilityDetails{
				vulnerability:  base,
				Recommendation: "do the thing",
			})
			return
		}
		_, _ = w.Write(vulnListJSON(items))
	})
	defer closeSrv()

	out := make(chan connector.Finding, 16)
	err := collectFindings(context.Background(), client, "scan-1", "res-1", "https://example.com", out)
	if err != nil {
		t.Fatalf("collectFindings: %v", err)
	}
	close(out)

	var got []connector.Finding
	for f := range out {
		if err := f.Validate(); err != nil {
			t.Fatalf("emitted an invalid finding: %v (%+v)", err, f)
		}
		got = append(got, f)
	}
	// ALL three items emitted — the failing one fell back to list data.
	if len(got) != 3 {
		t.Fatalf("emitted %d findings, want 3: %+v", len(got), got)
	}
	// Deterministic order: critical, medium, low.
	wantOrder := []struct {
		name     string
		severity string
	}{
		{"Crit One", "critical"},
		{"Med One", "medium"},
		{"Low One", "low"},
	}
	for i, w := range wantOrder {
		if got[i].Name != w.name || got[i].Severity != w.severity {
			t.Errorf("finding %d = (%q,%q), want (%q,%q)", i, got[i].Name, got[i].Severity, w.name, w.severity)
		}
	}
	// The detail-backed ones carry the recommendation; the failed one does not.
	if got[0].Solution != "do the thing" {
		t.Errorf("crit Solution = %q, want detail recommendation", got[0].Solution)
	}
	if got[1].Solution != "" {
		t.Errorf("med Solution = %q, want empty (detail failed → list fallback)", got[1].Solution)
	}
}

func TestCollectFindingsStableOrderAcrossRuns(t *testing.T) {
	// Two rows share vuln_id AND severity, differing only by affects_url. The
	// stable sort + MatchedAt tertiary key must give a run-independent order.
	items := []vulnerability{
		{VulnID: "dup", VTName: "Dup", Severity: 3, AffectsURL: "https://example.com/z", LastSeen: "2024-01-01"},
		{VulnID: "dup", VTName: "Dup", Severity: 3, AffectsURL: "https://example.com/a", LastSeen: "2024-01-01"},
	}

	run := func() []string {
		t.Helper()
		client, closeSrv := collectClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.Contains(r.URL.Path, "/vulnerabilities/") {
				id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
				base := items[0]
				for _, it := range items {
					if it.VulnID == id {
						base = it
					}
				}
				_ = json.NewEncoder(w).Encode(vulnerabilityDetails{vulnerability: base})
				return
			}
			_, _ = w.Write(vulnListJSON(items))
		})
		defer closeSrv()

		out := make(chan connector.Finding, 16)
		if err := collectFindings(context.Background(), client, "s", "r", "https://example.com", out); err != nil {
			t.Fatalf("collectFindings: %v", err)
		}
		close(out)
		var names []string
		for f := range out {
			names = append(names, f.Name+"@"+f.MatchedAt)
		}
		return names
	}

	first := run()
	second := run()
	if len(first) != 2 {
		t.Fatalf("got %d findings, want 2", len(first))
	}
	if strings.Join(first, "|") != strings.Join(second, "|") {
		t.Errorf("emit order not stable across runs: %v vs %v", first, second)
	}
	if !strings.HasSuffix(first[0], "@https://example.com/a") {
		t.Errorf("order = %v, want affects_url /a before /z (MatchedAt asc)", first)
	}
}

func TestCollectFindingsBoundedConcurrency(t *testing.T) {
	const n = 20
	items := make([]vulnerability, n)
	for i := 0; i < n; i++ {
		items[i] = vulnerability{
			VulnID:     "v" + string(rune('a'+i)),
			VTName:     "name",
			Severity:   2,
			AffectsURL: "https://example.com/x",
		}
	}

	var cur, max int64
	client, closeSrv := collectClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if !strings.Contains(r.URL.Path, "/vulnerabilities/") {
			_, _ = w.Write(vulnListJSON(items))
			return
		}
		// Record max concurrent in-flight detail requests.
		c := atomic.AddInt64(&cur, 1)
		for {
			m := atomic.LoadInt64(&max)
			if c <= m || atomic.CompareAndSwapInt64(&max, m, c) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt64(&cur, -1)

		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		_ = json.NewEncoder(w).Encode(vulnerabilityDetails{
			vulnerability: vulnerability{VulnID: id, VTName: "name", Severity: 2},
		})
	})
	defer closeSrv()

	out := make(chan connector.Finding, n*2)
	if err := collectFindings(context.Background(), client, "s", "r", "https://example.com", out); err != nil {
		t.Fatalf("collectFindings: %v", err)
	}
	close(out)
	count := 0
	for range out {
		count++
	}
	if count != n {
		t.Fatalf("emitted %d findings, want %d", count, n)
	}
	if m := atomic.LoadInt64(&max); m > detailWorkers {
		t.Errorf("max concurrent detail requests = %d, want <= %d", m, detailWorkers)
	}
}

func TestCollectFindingsCancelledNoSend(t *testing.T) {
	// A cancelled context fails the list call before any detail request; no
	// finding may be sent and the error must be context.Canceled.
	client, closeSrv := collectClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(vulnListJSON([]vulnerability{{VulnID: "v1", VTName: "One", Severity: 1}}))
	})
	defer closeSrv()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	out := make(chan connector.Finding, 4)
	err := collectFindings(ctx, client, "s", "r", "https://example.com", out)
	if err == nil {
		t.Fatal("expected an error for a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
	close(out)
	if n := len(out); n != 0 {
		t.Errorf("sent %d findings on a cancelled context, want 0", n)
	}
}
