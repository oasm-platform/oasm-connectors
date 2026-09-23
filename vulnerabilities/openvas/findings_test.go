// allow: SIZE_OK — plan T5 mandates a single findings_test.go holding the
// mapping, severity, determinism, and truncation-policy cases together.
package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// withFastBackoff shrinks the truncation-policy sleep so retry tests run in
// milliseconds instead of the production 2s.
func withFastBackoff(t *testing.T, d time.Duration) {
	t.Helper()
	old := resultsBackoff
	resultsBackoff = d
	t.Cleanup(func() { resultsBackoff = old })
}

// happyResult is a fully populated GMP result exercising every mapped field.
func happyResult() Result {
	r := Result{
		ID:               "res-1",
		Name:             "CVE-2021-1234 on 443/tcp",
		Port:             "443/tcp",
		Severity:         5.0,
		Description:      "Weak certificate.",
		CreationTime:     "2024-05-23T09:22:12Z",
		ModificationTime: "2024-05-24T10:00:00Z",
	}
	r.Host.IP = "10.0.0.5"
	r.Host.Hostname = "web.example.com"
	r.Nvt.OID = "1.3.6.1.4.1.25623.1.0.108098"
	r.Nvt.Name = "SSL Certificate Info"
	r.Nvt.Solution = "Upgrade the certificate"
	r.Nvt.Severities.Severity = []ResultSeverity{
		{Type: "cvss_base", Score: "5.0", Value: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
	}
	r.Nvt.Refs.Ref = []ResultRef{
		{Type: "cve", ID: "CVE-2021-1234"},
		{Type: "cwe", ID: "CWE-295"},
		{Type: "url", ID: "https://example.com/advisory"},
	}
	r.QOD.Value = 87
	return r
}

// TestMapResult_HappyPath: Given a full GMP result, When it is mapped, Then
// every expected field lands on the finding and Validate passes.
func TestMapResult_HappyPath(t *testing.T) {
	f := mapResult(happyResult()).toSDKFinding()

	if err := f.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if f.Name != "CVE-2021-1234 on 443/tcp" {
		t.Errorf("Name = %q", f.Name)
	}
	if f.Severity != "medium" {
		t.Errorf("Severity = %q, want medium (5.0)", f.Severity)
	}
	if f.Description != "Weak certificate." {
		t.Errorf("Description = %q", f.Description)
	}
	if f.Solution != "Upgrade the certificate" {
		t.Errorf("Solution = %q", f.Solution)
	}
	if f.Host != "web.example.com" {
		t.Errorf("Host = %q, want hostname over IP chardata", f.Host)
	}
	if f.IP != "10.0.0.5" {
		t.Errorf("IP = %q, want 10.0.0.5", f.IP)
	}
	if f.MatchedAt != "web.example.com:443/tcp" {
		t.Errorf("MatchedAt = %q", f.MatchedAt)
	}
	if len(f.Ports) != 1 || f.Ports[0] != "443/tcp" {
		t.Errorf("Ports = %v, want [443/tcp]", f.Ports)
	}
	if len(f.CVEID) != 1 || f.CVEID[0] != "CVE-2021-1234" {
		t.Errorf("CVEID = %v", f.CVEID)
	}
	if len(f.CWEID) != 1 || f.CWEID[0] != "CWE-295" {
		t.Errorf("CWEID = %v", f.CWEID)
	}
	if len(f.References) != 1 || f.References[0] != "https://example.com/advisory" {
		t.Errorf("References = %v", f.References)
	}
	if f.CVSSScore != 5.0 {
		t.Errorf("CVSSScore = %v, want 5.0", f.CVSSScore)
	}
	if f.CVSSMetrics != "AV:N/AC:L/Au:N/C:P/I:N/A:N" {
		t.Errorf("CVSSMetrics = %q", f.CVSSMetrics)
	}
	if f.Confidence != 87 {
		t.Errorf("Confidence = %v, want 87 (qod/value)", f.Confidence)
	}
	wantTS := time.Date(2024, 5, 23, 9, 22, 12, 0, time.UTC)
	if !f.Timestamp.Equal(wantTS) {
		t.Errorf("Timestamp = %v, want %v", f.Timestamp, wantTS)
	}
	wantMod := time.Date(2024, 5, 24, 10, 0, 0, 0, time.UTC)
	if !f.ModificationDate.Equal(wantMod) {
		t.Errorf("ModificationDate = %v, want %v", f.ModificationDate, wantMod)
	}
}

// TestMapSeverity_Boundaries: Given numeric severities at every table boundary
// plus out-of-range values, When mapped, Then each lands on its enum bucket
// and every result passes Validate (never out-of-enum).
func TestMapSeverity_Boundaries(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{0.0, "info"},
		{0.1, "low"},
		{3.9, "low"},
		{4.0, "medium"},
		{6.9, "medium"},
		{7.0, "high"},
		{8.9, "high"},
		{9.0, "critical"},
		{10.0, "critical"},
		{11.0, "info"}, // out of [0,10] → info, never an out-of-enum value
		{-1, "info"},
	}
	for _, tc := range cases {
		got := mapSeverity(tc.score)
		if got != tc.want {
			t.Errorf("mapSeverity(%v) = %q, want %q", tc.score, got, tc.want)
		}
		f := mapResult(Result{Severity: tc.score}).toSDKFinding()
		if err := f.Validate(); err != nil {
			t.Errorf("mapSeverity(%v): Validate: %v", tc.score, err)
		}
	}
}

// TestMapResult_NameFallback: Given results missing name layers, When mapped,
// Then Name falls back result → nvt/name → nvt@oid → "OpenVAS result" and is
// never empty.
func TestMapResult_NameFallback(t *testing.T) {
	cases := []struct {
		name string
		r    Result
		want string
	}{
		{"result name wins", Result{Name: "Result name", Nvt: ResultNvt{Name: "NVT name", OID: "1.3.6"}}, "Result name"},
		{"falls back to nvt name", Result{Name: "", Nvt: ResultNvt{Name: "NVT name", OID: "1.3.6"}}, "NVT name"},
		{"falls back to oid", Result{Name: "", Nvt: ResultNvt{Name: "", OID: "1.3.6"}}, "1.3.6"},
		{"falls back to constant", Result{}, "OpenVAS result"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := mapResult(tc.r).toSDKFinding()
			if f.Name != tc.want {
				t.Errorf("Name = %q, want %q", f.Name, tc.want)
			}
			if f.Name == "" {
				t.Fatal("Name is empty — would abort the stream")
			}
			if err := f.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

// TestMapResult_HostAndMatchedAt: Given hosts with/without a hostname child,
// IP and non-IP chardata, and ports present/absent, When mapped, Then Host
// prefers hostname, IP only holds IP literals, and MatchedAt is host[:port].
func TestMapResult_HostAndMatchedAt(t *testing.T) {
	withHostname := Result{Port: "443/tcp"}
	withHostname.Host.IP = "10.0.0.5"
	withHostname.Host.Hostname = "web.example.com"

	ipOnly := Result{Port: "22/tcp"}
	ipOnly.Host.IP = "10.0.0.6"

	nameOnly := Result{Port: ""}
	nameOnly.Host.IP = "db.internal"

	nonIPLiteral := Result{Port: "5432/tcp"}
	nonIPLiteral.Host.IP = "db.internal"

	cases := []struct {
		name      string
		r         Result
		wantHost  string
		wantIP    string
		wantMatch string
		wantPorts []string
	}{
		{"hostname preferred over IP", withHostname, "web.example.com", "10.0.0.5", "web.example.com:443/tcp", []string{"443/tcp"}},
		{"IP chardata fallback", ipOnly, "10.0.0.6", "10.0.0.6", "10.0.0.6:22/tcp", []string{"22/tcp"}},
		{"no port → host only", nameOnly, "db.internal", "", "db.internal", nil},
		{"non-IP chardata → IP empty", nonIPLiteral, "db.internal", "", "db.internal:5432/tcp", []string{"5432/tcp"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := mapResult(tc.r).toSDKFinding()
			if f.Host != tc.wantHost {
				t.Errorf("Host = %q, want %q", f.Host, tc.wantHost)
			}
			if f.IP != tc.wantIP {
				t.Errorf("IP = %q, want %q", f.IP, tc.wantIP)
			}
			if f.MatchedAt != tc.wantMatch {
				t.Errorf("MatchedAt = %q, want %q", f.MatchedAt, tc.wantMatch)
			}
			if len(f.Ports) != len(tc.wantPorts) {
				t.Fatalf("Ports = %v, want %v", f.Ports, tc.wantPorts)
			}
			for i := range tc.wantPorts {
				if f.Ports[i] != tc.wantPorts[i] {
					t.Errorf("Ports = %v, want %v", f.Ports, tc.wantPorts)
				}
			}
		})
	}
}

// TestMapResult_SplitsRefs: Given mixed ref types, When mapped, Then cve / cwe
// / url land on their own fields and unknown types are ignored.
func TestMapResult_SplitsRefs(t *testing.T) {
	r := Result{}
	r.Nvt.Refs.Ref = []ResultRef{
		{Type: "cve", ID: "CVE-2024-0001"},
		{Type: "cwe", ID: "CWE-79"},
		{Type: "url", ID: "https://example.com/a"},
		{Type: "bid", ID: "12345"},
		{Type: "url", ID: "https://example.com/b"},
	}
	f := mapResult(r).toSDKFinding()

	if len(f.CVEID) != 1 || f.CVEID[0] != "CVE-2024-0001" {
		t.Errorf("CVEID = %v", f.CVEID)
	}
	if len(f.CWEID) != 1 || f.CWEID[0] != "CWE-79" {
		t.Errorf("CWEID = %v", f.CWEID)
	}
	if len(f.References) != 2 || f.References[0] != "https://example.com/a" || f.References[1] != "https://example.com/b" {
		t.Errorf("References = %v, want both url refs in order", f.References)
	}
}

// TestMapResult_CVSSBaseV2PickedUp: Given a result whose only cvss entry is
// cvss_base_v2 (score differing from the result severity), When mapped, Then
// the entry's score and vector win while the severity enum still comes from
// the numeric result severity.
func TestMapResult_CVSSBaseV2PickedUp(t *testing.T) {
	r := Result{Severity: 7.0}
	r.Nvt.Severities.Severity = []ResultSeverity{
		{Type: "cvss_base_v2", Score: "4.3", Value: "AV:N/AC:L/Au:N/C:P/I:N/A:N"},
	}
	f := mapResult(r).toSDKFinding()

	if f.CVSSScore != 4.3 {
		t.Errorf("CVSSScore = %v, want 4.3 from cvss_base_v2 entry", f.CVSSScore)
	}
	if f.CVSSMetrics != "AV:N/AC:L/Au:N/C:P/I:N/A:N" {
		t.Errorf("CVSSMetrics = %q, want cvss_base_v2 vector", f.CVSSMetrics)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want high (result severity 7.0 drives the enum)", f.Severity)
	}
}

// TestMapResult_InvalidTimeIsZero: Given unparseable creation/modification
// times, When mapped, Then both timestamps are the zero time (omitted on the
// wire); parseable RFC3339 inputs land in UTC.
func TestMapResult_InvalidTimeIsZero(t *testing.T) {
	r := Result{CreationTime: "not-a-timestamp", ModificationTime: "2024-13-99T99:99:99Z"}
	f := mapResult(r).toSDKFinding()
	if !f.Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero for invalid creation_time", f.Timestamp)
	}
	if !f.ModificationDate.IsZero() {
		t.Errorf("ModificationDate = %v, want zero for invalid modification_time", f.ModificationDate)
	}

	ok := Result{CreationTime: "2024-05-23T11:22:12+02:00"}
	got := mapResult(ok).toSDKFinding()
	want := time.Date(2024, 5, 23, 9, 22, 12, 0, time.UTC)
	if !got.Timestamp.Equal(want) || got.Timestamp.Location() != time.UTC {
		t.Errorf("Timestamp = %v, want %v UTC", got.Timestamp, want)
	}
}

// orderKey flattens findings to a comparable byte string for order assertions.
func orderKey(fs []connector.Finding) string {
	var b strings.Builder
	for _, f := range fs {
		b.WriteString(f.Host)
		b.WriteByte(0)
		b.WriteString(f.MatchedAt)
		b.WriteByte(0)
		b.WriteString(f.Name)
		b.WriteByte('\n')
	}
	return b.String()
}

// deterministicSet builds the same four results in two different input orders,
// including a host/port/oid tie broken only by result id.
func deterministicSet() (permA, permB []Result) {
	mk := func(id, host, port, oid, name string) Result {
		r := Result{ID: id, Port: port, Name: name}
		r.Host.IP = host
		r.Nvt.OID = oid
		return r
	}
	r1 := mk("r1", "10.0.0.1", "443/tcp", "1.1.1", "vuln-r1")
	r2 := mk("r2", "10.0.0.1", "443/tcp", "1.1.1", "vuln-r2") // tie: only id differs
	r3 := mk("r3", "10.0.0.1", "22/tcp", "3.3.3", "vuln-r3")
	r5 := mk("r5", "10.0.0.2", "80/tcp", "2.2.2", "vuln-r5")
	return []Result{r5, r2, r3, r1}, []Result{r1, r3, r5, r2}
}

// TestMapResults_DeterministicAcrossShuffle: Given the same results shuffled
// two ways, When mapped twice, Then both emit byte-identical order — sorted by
// (host, port, oid) with id as the total tiebreaker.
func TestMapResults_DeterministicAcrossShuffle(t *testing.T) {
	wantOrder := "" +
		"10.0.0.1\x0010.0.0.1:22/tcp\x00vuln-r3\n" + // host asc, port 22 < 443
		"10.0.0.1\x0010.0.0.1:443/tcp\x00vuln-r1\n" + // same host/port/oid → id r1 < r2
		"10.0.0.1\x0010.0.0.1:443/tcp\x00vuln-r2\n" +
		"10.0.0.2\x0010.0.0.2:80/tcp\x00vuln-r5\n" // host 10.0.0.2 last

	permA, permB := deterministicSet()
	keyA := orderKey(mapResults(permA))
	keyB := orderKey(mapResults(permB))

	if keyA != keyB {
		t.Errorf("orders differ across shuffles:\nA:\n%s\nB:\n%s", keyA, keyB)
	}
	if keyA != wantOrder {
		t.Errorf("order =\n%s\nwant\n%s", keyA, wantOrder)
	}
}

// shortFetch returns one result but reports five — a persistently truncated
// set for the bounded-retry policy.
func shortFetch(_ context.Context) ([]Result, int, bool, error) {
	return []Result{{ID: "r1", Name: "only"}}, 5, true, nil
}

// TestFetchResults_WhenCountPresentAndShort_ThenRetriesThenTruncatedError:
// Given a reported count above the delivered rows on every attempt, When
// fetched, Then it re-fetches up to maxResultRefetches times and fails with
// the retryable truncation error (never streams a partial set).
func TestFetchResults_WhenCountPresentAndShort_ThenRetriesThenTruncatedError(t *testing.T) {
	withFastBackoff(t, time.Millisecond)
	calls := 0
	fetch := func(ctx context.Context) ([]Result, int, bool, error) {
		calls++
		return shortFetch(ctx)
	}

	_, err := fetchResults(context.Background(), fetch)
	if err == nil {
		t.Fatal("fetchResults returned nil, want truncation error")
	}
	if want := "retryable: openvas: results truncated (got 1 of 5)"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err.Error(), want)
	}
	// 1 initial fetch + maxResultRefetches re-fetches.
	if want := 1 + maxResultRefetches; calls != want {
		t.Errorf("fetch called %d times, want %d", calls, want)
	}
}

// TestFetchResults_WhenRefetchCompletes_ThenAccepts: Given a short first fetch
// that completes on re-fetch, When fetched, Then the full set is accepted with
// no truncation error.
func TestFetchResults_WhenRefetchCompletes_ThenAccepts(t *testing.T) {
	withFastBackoff(t, time.Millisecond)
	calls := 0
	fetch := func(_ context.Context) ([]Result, int, bool, error) {
		calls++
		if calls == 1 {
			return []Result{{ID: "r1"}}, 2, true, nil
		}
		return []Result{{ID: "r1"}, {ID: "r2"}}, 2, true, nil
	}

	results, err := fetchResults(context.Background(), fetch)
	if err != nil {
		t.Fatalf("fetchResults: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("len(results) = %d, want 2", len(results))
	}
	if calls != 2 {
		t.Errorf("fetch called %d times, want 2 (initial + 1)", calls)
	}
}

// TestFetchResults_WhenNoCount_ThenSettlesOnceAndAccepts: Given a response
// without result_count, When fetched, Then exactly one settle re-fetch happens
// and the returned set is accepted.
func TestFetchResults_WhenNoCount_ThenSettlesOnceAndAccepts(t *testing.T) {
	withFastBackoff(t, time.Millisecond)
	calls := 0
	fetch := func(_ context.Context) ([]Result, int, bool, error) {
		calls++
		return []Result{{ID: "r1", Name: "n"}}, 0, false, nil
	}

	results, err := fetchResults(context.Background(), fetch)
	if err != nil {
		t.Fatalf("fetchResults: %v", err)
	}
	if len(results) != 1 {
		t.Errorf("len(results) = %d, want the accepted set of 1", len(results))
	}
	if calls != 2 {
		t.Errorf("fetch called %d times, want 2 (initial + at most one settle retry)", calls)
	}
}

// TestFetchResults_WhenCancelledDuringBackoff_ThenCancelledError: Given a
// context cancelled before the backoff sleep elapses, When fetched, Then the
// wait unblocks immediately with the T3-style retryable cancelled error
// (errors.Is context.Canceled) and no further fetch happens.
func TestFetchResults_WhenCancelledDuringBackoff_ThenCancelledError(t *testing.T) {
	old := resultsBackoff
	resultsBackoff = time.Hour // would hang without the ctx check
	t.Cleanup(func() { resultsBackoff = old })

	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	fetch := func(context.Context) ([]Result, int, bool, error) {
		calls++
		cancel() // cancelled while the policy is about to sleep
		return shortFetch(ctx)
	}

	_, err := fetchResults(ctx, fetch)
	if err == nil {
		t.Fatal("fetchResults returned nil, want cancelled error")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want errors.Is(context.Canceled)", err)
	}
	if !strings.HasPrefix(err.Error(), "retryable: openvas: cancelled:") {
		t.Errorf("Error() = %q, want retryable: openvas: cancelled: prefix", err.Error())
	}
	if calls != 1 {
		t.Errorf("fetch called %d times, want 1 (aborted before retry)", calls)
	}
}

// collectResultsOK delivers two complete results (count matches) with the
// out-of-order rows deliberately shuffled server-side.
const collectResultsOK = `<get_results_response status="200" status_text="OK">` +
	`<result id="res-b"><name>BB vuln</name><host>10.0.0.6</host><port>80/tcp</port>` +
	`<nvt oid="2.2.2"><name>nvt-b</name></nvt><threat>Low</threat><severity>3.0</severity>` +
	`<qod><value>80</value></qod><description>db</description>` +
	`<creation_time>2024-01-01T00:00:00Z</creation_time>` +
	`<modification_time>2024-01-01T00:00:00Z</modification_time></result>` +
	`<result id="res-a"><name>AA vuln</name><host>10.0.0.5</host><port>443/tcp</port>` +
	`<nvt oid="1.1.1"><name>nvt-a</name></nvt><threat>High</threat><severity>7.5</severity>` +
	`<qod><value>90</value></qod><description>da</description>` +
	`<creation_time>2024-01-01T00:00:00Z</creation_time>` +
	`<modification_time>2024-01-01T00:00:00Z</modification_time></result>` +
	`<result_count><filtered>2</filtered><page>2</page></result_count>` +
	`</get_results_response>`

// TestCollectFindings_HappyPath: Given a complete get_results response with
// shuffled rows, When collected, Then findings stream in deterministic host
// order and every emitted finding passes Validate.
func TestCollectFindings_HappyPath(t *testing.T) {
	f := newFakeGMP(t)
	f.script(collectResultsOK)
	c := dialFake(t, f)

	out := make(chan connector.Finding, 8)
	if err := collectFindings(context.Background(), c, "task-1", "example.com", out); err != nil {
		t.Fatalf("collectFindings: %v", err)
	}
	if got := len(out); got != 2 {
		t.Fatalf("emitted %d findings, want 2", got)
	}
	first, second := <-out, <-out
	if first.Name != "AA vuln" || second.Name != "BB vuln" {
		t.Errorf("emit order = %q then %q, want AA vuln then BB vuln (host sort)", first.Name, second.Name)
	}
	for _, fc := range []connector.Finding{first, second} {
		if err := fc.Validate(); err != nil {
			t.Errorf("Validate(%q): %v", fc.Name, err)
		}
	}
	if got := len(out); got != 0 {
		t.Errorf("%d extra findings left in channel", got)
	}
}

// TestCollectFindings_WhenResponseUndecodable_ThenError: Given a results
// document the decoder cannot parse, When collected, Then the already-prefixed
// error surfaces unchanged — a bad response is never silently dropped.
func TestCollectFindings_WhenResponseUndecodable_ThenError(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<get_results_response status="200" status_text="OK"><result id="r1"><severity>not-a-number</severity></result></get_results_response>`)
	c := dialFake(t, f)

	out := make(chan connector.Finding, 8)
	err := collectFindings(context.Background(), c, "task-1", "example.com", out)
	if err == nil {
		t.Fatal("collectFindings returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Errorf("Error() = %q, want fatal: prefix", err.Error())
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("Error() = %q, want decode error", err.Error())
	}
	if got := len(out); got != 0 {
		t.Errorf("emitted %d findings before failing, want 0", got)
	}
}
