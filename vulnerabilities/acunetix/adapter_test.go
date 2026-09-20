package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// ---------------------------------------------------------------------------
// Route constants. The fake records `METHOD path` for every request; each test
// asserts the exact multiset of routes hit.
// ---------------------------------------------------------------------------

const (
	rListTargets  = "GET /api/v1/targets"
	rCreateTarget = "POST /api/v1/targets"
	rDeleteTarget = "DELETE /api/v1/targets/t-created"
	rCreateScan   = "POST /api/v1/scans"
	rGetScan      = "GET /api/v1/scans/scan-uuid"
	rDeleteScan   = "DELETE /api/v1/scans/scan-uuid"
	rResults      = "GET /api/v1/scans/scan-uuid/results"
	rVulns        = "GET /api/v1/scans/scan-uuid/results/res-1/vulnerabilities"
)

func vulnRoute(resultID string) string {
	return "GET /api/v1/scans/scan-uuid/results/" + resultID + "/vulnerabilities"
}

func detailRoute(vulnID string) string {
	return "GET /api/v1/scans/scan-uuid/results/res-1/vulnerabilities/" + vulnID
}

// ---------------------------------------------------------------------------
// Fake Acunetix state machine
// ---------------------------------------------------------------------------

type fakeAcunetix struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex

	// GET /targets
	targets []target
	// POST /targets
	createTargetID  string
	createTargetErr int

	// GET /scans/{id}: one scripted entry per poll; a nil entry yields a nil
	// current_session. When the script is exhausted the last entry repeats.
	scanID    string
	statuses  []*scanInfo
	statusIdx int
	scanErr   int

	results    []scanResultItem
	resultsErr int

	vulnPages   []vulnerabilityListResponse
	vulnPageIdx int

	details   map[string]vulnerabilityDetails
	detailErr map[string]int

	routes       []string
	vulnQueries  []string
	badVulnQuery []string
}

func newFakeAcunetixBare(t *testing.T) *fakeAcunetix {
	return &fakeAcunetix{
		t:              t,
		createTargetID: "t-created",
		scanID:         "scan-uuid",
		details:        map[string]vulnerabilityDetails{},
		detailErr:      map[string]int{},
	}
}

func newFakeAcunetix(t *testing.T) *fakeAcunetix {
	t.Helper()
	f := newFakeAcunetixBare(t)
	f.server = httptest.NewServer(f.mux())
	t.Cleanup(f.server.Close)
	return f
}

func newFakeAcunetixTLS(t *testing.T) *fakeAcunetix {
	t.Helper()
	f := newFakeAcunetixBare(t)
	f.server = httptest.NewTLSServer(f.mux())
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAcunetix) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/targets", f.handleListTargets)
	mux.HandleFunc("POST /api/v1/targets", f.handleCreateTarget)
	mux.HandleFunc("DELETE /api/v1/targets/{id}", f.handleDeleteTarget)
	mux.HandleFunc("POST /api/v1/scans", f.handleCreateScan)
	mux.HandleFunc("GET /api/v1/scans/{id}", f.handleGetScan)
	mux.HandleFunc("DELETE /api/v1/scans/{id}", f.handleDeleteScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/results", f.handleGetResults)
	mux.HandleFunc("GET /api/v1/scans/{id}/results/{rid}/vulnerabilities", f.handleListVulns)
	mux.HandleFunc("GET /api/v1/scans/{id}/results/{rid}/vulnerabilities/{vid}", f.handleGetVuln)
	return mux
}

// env points the connector at this fake via OASM_CONFIG. clearAcunetixEnv
// (acunetix_test.go) isolates the process env first.
func (f *fakeAcunetix) env(t *testing.T, extra map[string]any) {
	t.Helper()
	f.envWithURL(t, f.server.URL, extra)
}

func (f *fakeAcunetix) envWithURL(t *testing.T, url string, extra map[string]any) {
	t.Helper()
	clearAcunetixEnv(t)
	m := map[string]any{"url": url, "apiKey": "k"}
	for k, v := range extra {
		m[k] = v
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	t.Setenv("OASM_CONFIG", string(b))
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Code: status, Reason: "boom", Details: []string{"x"}})
}

func (f *fakeAcunetix) record(r *http.Request) {
	f.mu.Lock()
	f.routes = append(f.routes, r.Method+" "+r.URL.Path)
	f.mu.Unlock()
}

func (f *fakeAcunetix) handleListTargets(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	f.mu.Lock()
	targets := append([]target(nil), f.targets...)
	f.mu.Unlock()
	writeJSON(w, targetListResponse{
		Targets:    targets,
		Pagination: pagination{Cursors: []*string{nil, nil}},
	})
}

func (f *fakeAcunetix) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	f.mu.Lock()
	status, id := f.createTargetErr, f.createTargetID
	f.mu.Unlock()
	if status != 0 {
		writeErr(w, status)
		return
	}
	w.Header().Set("Location", "/api/v1/targets/"+id)
	writeJSON(w, target{TargetID: id, Address: "https://example.com"})
}

func (f *fakeAcunetix) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeAcunetix) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	f.mu.Lock()
	id := f.scanID
	f.mu.Unlock()
	// The scan id is exposed ONLY via the Location header (no body).
	w.Header().Set("Location", "/api/v1/scans/"+id)
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeAcunetix) handleGetScan(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	f.mu.Lock()
	status := f.scanErr
	var info *scanInfo
	if len(f.statuses) == 0 {
		info = &scanInfo{Status: "completed"}
	} else {
		idx := f.statusIdx
		if idx < len(f.statuses) {
			f.statusIdx++
		}
		if idx >= len(f.statuses) {
			idx = len(f.statuses) - 1
		}
		info = f.statuses[idx]
	}
	f.mu.Unlock()
	if status != 0 {
		writeErr(w, status)
		return
	}
	writeJSON(w, scanItemResponse{ScanID: r.PathValue("id"), CurrentSession: info})
}

func (f *fakeAcunetix) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeAcunetix) handleGetResults(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	f.mu.Lock()
	status, results := f.resultsErr, append([]scanResultItem(nil), f.results...)
	f.mu.Unlock()
	if status != 0 {
		writeErr(w, status)
		return
	}
	writeJSON(w, scanResultListResponse{
		Results:    results,
		Pagination: pagination{Cursors: []*string{nil, nil}},
	})
}

func (f *fakeAcunetix) handleListVulns(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	f.mu.Lock()
	q := r.URL.RawQuery
	f.vulnQueries = append(f.vulnQueries, q)
	if strings.Contains(q, "l=") {
		f.badVulnQuery = append(f.badVulnQuery, q)
	}
	var page vulnerabilityListResponse
	if f.vulnPageIdx < len(f.vulnPages) {
		page = f.vulnPages[f.vulnPageIdx]
	}
	f.vulnPageIdx++
	f.mu.Unlock()
	writeJSON(w, page)
}

func (f *fakeAcunetix) handleGetVuln(w http.ResponseWriter, r *http.Request) {
	f.record(r)
	vid := r.PathValue("vid")
	f.mu.Lock()
	status, d, ok := f.detailErr[vid], f.details[vid], false
	if _, present := f.details[vid]; present {
		ok = true
	}
	f.mu.Unlock()
	if status != 0 {
		writeErr(w, status)
		return
	}
	if !ok {
		d = vulnerabilityDetails{vulnerability: vulnerability{VulnID: vid, VTName: "fallback " + vid, Severity: 1}}
	}
	writeJSON(w, d)
}

// countPrefix counts recorded routes with the given prefix.
func (f *fakeAcunetix) countPrefix(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.routes {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

// countRoute counts exact `METHOD path` hits (no query; routes never carry one).
func (f *fakeAcunetix) countRoute(route string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.routes {
		if r == route {
			n++
		}
	}
	return n
}

func (f *fakeAcunetix) deleteCounts() (targets, scans int) {
	return f.countPrefix("DELETE /api/v1/targets/"), f.countPrefix("DELETE /api/v1/scans/")
}

func (f *fakeAcunetix) routesSnapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.routes...)
}

// assertRoutes compares the recorded route multiset (order-independent) to want.
func assertRoutes(t *testing.T, f *fakeAcunetix, want ...string) {
	t.Helper()
	got := f.routesSnapshot()
	exp := append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(exp)
	if !reflect.DeepEqual(got, exp) {
		t.Errorf("routes =\n  %v\nwant\n  %v", got, exp)
	}
}

func assertNoDeletes(t *testing.T, f *fakeAcunetix) {
	t.Helper()
	if targets, scans := f.deleteCounts(); targets != 0 || scans != 0 {
		t.Errorf("deletes = targets:%d scans:%d, want 0/0 (retention-on-failure)", targets, scans)
	}
}

// shortenPoll swaps pollInterval for a test and restores it on cleanup.
func shortenPoll(t *testing.T, d time.Duration) {
	t.Helper()
	old := pollInterval
	pollInterval = d
	t.Cleanup(func() { pollInterval = old })
}

func executeSync(t *testing.T, ctx context.Context, target string) ([]connector.Finding, error) {
	t.Helper()
	out := make(chan connector.Finding, 128)
	err := (&AcunetixAdapter{}).Execute(ctx, map[string]any{"target": target}, out)
	close(out)
	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

// completeScanTail configures a minimal successful scan tail: one result and one
// empty vulnerability page, so tests that are not about pagination can run end
// to end.
func (f *fakeAcunetix) completeScanTail() {
	f.results = []scanResultItem{{ResultID: "res-1", ScanID: "scan-uuid", StartDate: "2024-01-01T00:00:00Z"}}
	f.vulnPages = []vulnerabilityListResponse{{Pagination: pagination{Cursors: []*string{nil, nil}}}}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestAdapterValidateNoOp(t *testing.T) {
	a := AcunetixAdapter{}
	for _, in := range []map[string]any{nil, {}, {"target": "x"}, {"target": 42, "z": "y"}} {
		if err := a.Validate(context.Background(), in); err != nil {
			t.Errorf("Validate(%v) = %v, want nil", in, err)
		}
	}
}

func TestExecuteMissingTarget(t *testing.T) {
	a := AcunetixAdapter{}
	for _, raw := range []any{nil, "", "   ", "\t\n"} {
		in := map[string]any{}
		if raw != nil {
			in["target"] = raw
		}
		err := a.Execute(context.Background(), in, make(chan connector.Finding, 1))
		if err == nil || !strings.Contains(err.Error(), "target required") {
			t.Errorf("Execute(target=%v) err = %v, want 'target required'", raw, err)
		}
	}
}

func TestExecuteMissingURL(t *testing.T) {
	clearAcunetixEnv(t)
	t.Setenv("OASM_CONFIG", `{"apiKey":"k"}`)
	err := (&AcunetixAdapter{}).Execute(context.Background(), map[string]any{"target": "x"}, make(chan connector.Finding, 1))
	if err == nil || !strings.Contains(err.Error(), "URL required") {
		t.Fatalf("err = %v, want URL required", err)
	}
}

func TestExecuteMissingAPIKey(t *testing.T) {
	clearAcunetixEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://x"}`)
	err := (&AcunetixAdapter{}).Execute(context.Background(), map[string]any{"target": "x"}, make(chan connector.Finding, 1))
	if err == nil || !strings.Contains(err.Error(), "API key required") {
		t.Fatalf("err = %v, want API key required", err)
	}
}

func TestExecuteHappyCreatePath(t *testing.T) {
	f := newFakeAcunetix(t)
	f.statuses = []*scanInfo{
		{Status: "queued"},
		{Status: "processing"},
		{Status: "completed", ScanSessionID: "sess-other"},
	}
	f.results = []scanResultItem{{ResultID: "res-1", ScanID: "scan-uuid", StartDate: "2024-01-01T00:00:00Z"}}
	f.vulnPages = []vulnerabilityListResponse{
		{
			Vulnerabilities: []vulnerability{{VulnID: "vuln-a", VTName: "SQL Injection", Severity: 4, AffectsURL: "https://example.com/a", LastSeen: "2024-02-01T00:00:00Z"}},
			Pagination:      pagination{Cursors: []*string{nil, strptr("c1")}},
		},
		{
			Vulnerabilities: []vulnerability{{VulnID: "vuln-b", VTName: "Open Redirect", Severity: 2, AffectsURL: "https://example.com/b", LastSeen: "2024-02-02T00:00:00Z"}},
			Pagination:      pagination{Cursors: []*string{strptr("c1"), nil}},
		},
	}
	f.details["vuln-a"] = vulnerabilityDetails{
		vulnerability:  vulnerability{VulnID: "vuln-a", VTName: "SQL Injection", Severity: 4, AffectsURL: "https://example.com/a", LastSeen: "2024-02-01T00:00:00Z"},
		Recommendation: "parameterize queries",
		CVSS4Score:     9.8,
		CVSS4:          "CVSS:4.0/AV:N",
	}
	f.details["vuln-b"] = vulnerabilityDetails{
		vulnerability:  vulnerability{VulnID: "vuln-b", VTName: "Open Redirect", Severity: 2, AffectsURL: "https://example.com/b", LastSeen: "2024-02-02T00:00:00Z"},
		Recommendation: "validate redirect targets",
		CVSSScore:      5.4,
		CVSS3:          "CVSS:3.1/AV:N",
	}

	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	findings, err := executeSync(t, context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	if findings[0].Name != "SQL Injection" || findings[0].Severity != "critical" || findings[0].CVSSScore != 9.8 {
		t.Errorf("findings[0] = %+v, want critical SQL Injection cvss 9.8", findings[0])
	}
	if findings[1].Name != "Open Redirect" || findings[1].Severity != "medium" || findings[1].CVSSScore != 5.4 {
		t.Errorf("findings[1] = %+v, want medium Open Redirect cvss 5.4", findings[1])
	}
	for _, fnd := range findings {
		if err := fnd.Validate(); err != nil {
			t.Errorf("emitted invalid finding: %v (%+v)", err, fnd)
		}
	}

	f.mu.Lock()
	queries := append([]string(nil), f.vulnQueries...)
	bad := append([]string(nil), f.badVulnQuery...)
	f.mu.Unlock()
	if len(bad) != 0 {
		t.Errorf("vulnerability requests carried l=: %v", bad)
	}
	if !reflect.DeepEqual(queries, []string{"", "c=c1"}) {
		t.Errorf("vuln queries = %v, want [\"\" \"c=c1\"] (c only after page 1)", queries)
	}

	assertRoutes(t, f,
		rListTargets, rCreateTarget, rCreateScan,
		rGetScan, rGetScan, rGetScan,
		rResults, rVulns, rVulns,
		detailRoute("vuln-a"), detailRoute("vuln-b"),
		rDeleteTarget,
	)
}

// TestExecuteReuseSafety is the P0 regression: a target the connector did not
// create must never be deleted; only the scan is.
func TestExecuteReuseSafety(t *testing.T) {
	f := newFakeAcunetix(t)
	f.targets = []target{{TargetID: "t-existing", Address: "https://example.com"}}
	f.completeScanTail()
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	findings, err := executeSync(t, context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("got %d findings, want 0", len(findings))
	}

	if n := f.countPrefix(rCreateTarget); n != 0 {
		t.Errorf("POST /targets = %d, want 0 (target was reused)", n)
	}
	if n := f.countPrefix("DELETE /api/v1/targets/"); n != 0 {
		t.Errorf("DELETE /targets = %d, want 0 (never delete a reused target)", n)
	}
	if n := f.countPrefix(rDeleteScan); n != 1 {
		t.Errorf("DELETE /scans = %d, want 1", n)
	}

	assertRoutes(t, f, rListTargets, rCreateScan, rGetScan, rResults, rVulns, rDeleteScan)
}

func TestExecuteNormalizationMatchReuse(t *testing.T) {
	f := newFakeAcunetix(t)
	// Stored address differs only by scheme case, default port and a trailing
	// slash — it must still be reused.
	f.targets = []target{{TargetID: "t-normalized", Address: "HTTP://Example.COM:80/"}}
	f.completeScanTail()
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	if _, err := executeSync(t, context.Background(), "http://example.com"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if n := f.countPrefix(rCreateTarget); n != 0 {
		t.Errorf("POST /targets = %d, want 0 (normalization-match reuse)", n)
	}
	if n := f.countPrefix("DELETE /api/v1/targets/"); n != 0 {
		t.Errorf("DELETE /targets = %d, want 0", n)
	}
	if n := f.countPrefix(rDeleteScan); n != 1 {
		t.Errorf("DELETE /scans = %d, want 1", n)
	}
}

// TestExecuteOverScopeGuard: a different path must NOT be bridged onto an
// existing target.
func TestExecuteOverScopeGuard(t *testing.T) {
	f := newFakeAcunetix(t)
	f.targets = []target{{TargetID: "t-root", Address: "https://example.com"}}
	f.completeScanTail()
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	if _, err := executeSync(t, context.Background(), "https://example.com/app"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if n := f.countPrefix(rCreateTarget); n != 1 {
		t.Errorf("POST /targets = %d, want 1 (different path is a new target)", n)
	}
	// The created target is deleted (cascading its scan), never the pre-existing one.
	if n := f.countPrefix(rDeleteTarget); n != 1 {
		t.Errorf("DELETE /targets/t-created = %d, want 1", n)
	}
	if n := f.countPrefix("DELETE /api/v1/targets/t-root"); n != 0 {
		t.Errorf("DELETE /targets/t-root = %d, want 0", n)
	}
	if n := f.countPrefix("DELETE /api/v1/scans/"); n != 0 {
		t.Errorf("DELETE /scans = %d, want 0 (target delete cascades)", n)
	}
}

func TestExecuteSingleCursorPagination(t *testing.T) {
	f := newFakeAcunetix(t)
	f.completeScanTail()
	f.vulnPages = []vulnerabilityListResponse{
		{
			Vulnerabilities: []vulnerability{{VulnID: "vuln-a", VTName: "A", Severity: 1, AffectsURL: "https://example.com/a"}},
			Pagination:      pagination{Cursors: []*string{strptr("c1")}},
		},
		{
			Vulnerabilities: []vulnerability{{VulnID: "vuln-b", VTName: "B", Severity: 1, AffectsURL: "https://example.com/b"}},
			Pagination:      pagination{Cursors: []*string{nil, nil}},
		},
	}
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	findings, err := executeSync(t, context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2 (single cursor must not truncate)", len(findings))
	}
	if n := f.countRoute(rVulns); n != 2 {
		t.Errorf("vulnerability page requests = %d, want 2", n)
	}
	f.mu.Lock()
	queries := append([]string(nil), f.vulnQueries...)
	f.mu.Unlock()
	if !reflect.DeepEqual(queries, []string{"", "c=c1"}) {
		t.Errorf("queries = %v, want [\"\" \"c=c1\"]", queries)
	}
}

func TestExecuteIncompletePagination(t *testing.T) {
	f := newFakeAcunetix(t)
	f.completeScanTail()
	items := make([]vulnerability, 100)
	for i := range items {
		items[i] = vulnerability{VulnID: "v", VTName: "x", Severity: 1}
	}
	f.vulnPages = []vulnerabilityListResponse{{
		Vulnerabilities: items,
		Pagination:      pagination{Count: 150, Cursors: []*string{nil, nil}},
	}}
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	_, err := executeSync(t, context.Background(), "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "pagination incomplete: got 100 of 150") {
		t.Fatalf("err = %v, want pagination incomplete loud error", err)
	}
	assertNoDeletes(t, f)
}

func TestExecuteTrailingSlashBaseURL(t *testing.T) {
	f := newFakeAcunetix(t)
	f.completeScanTail()
	f.envWithURL(t, f.server.URL+"/", nil)
	shortenPoll(t, time.Millisecond)

	if _, err := executeSync(t, context.Background(), "https://example.com"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// Base URL with a trailing slash must still hit /api/v1/... exactly once.
	assertRoutes(t, f,
		rListTargets, rCreateTarget, rCreateScan,
		rGetScan, rResults, rVulns,
		rDeleteTarget,
	)
}

func TestExecuteDisableTLSChecks(t *testing.T) {
	f := newFakeAcunetixTLS(t)
	f.completeScanTail()
	shortenPoll(t, time.Millisecond)

	t.Run("without flag the self-signed cert fails", func(t *testing.T) {
		f.env(t, nil)
		if _, err := executeSync(t, context.Background(), "https://example.com"); err == nil {
			t.Fatal("want a TLS error without disableTlsChecks")
		}
	})

	t.Run("with flag the request succeeds", func(t *testing.T) {
		f.env(t, map[string]any{"disableTlsChecks": true})
		if _, err := executeSync(t, context.Background(), "https://example.com"); err != nil {
			t.Fatalf("Execute with disableTlsChecks: %v", err)
		}
	})
}

func TestExecuteNon2xxBoom(t *testing.T) {
	f := newFakeAcunetix(t)
	f.scanErr = http.StatusInternalServerError
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	_, err := executeSync(t, context.Background(), "https://example.com")
	if err == nil {
		t.Fatal("want an error for a 500 scan-status response")
	}
	for _, want := range []string{"boom", "500"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err %q missing %q", err.Error(), want)
		}
	}
	assertNoDeletes(t, f)
}

func TestExecuteNilCurrentSessionThenCompleted(t *testing.T) {
	f := newFakeAcunetix(t)
	f.statuses = []*scanInfo{nil, {Status: "completed", ScanSessionID: ""}}
	f.completeScanTail()
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	if _, err := executeSync(t, context.Background(), "https://example.com"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if n := f.countRoute(rGetScan); n != 2 {
		t.Errorf("scan polls = %d, want 2 (nil current_session then completed)", n)
	}
}

func TestExecuteUnknownStatusKeepsPolling(t *testing.T) {
	f := newFakeAcunetix(t)
	f.statuses = []*scanInfo{{Status: "pausing"}, {Status: "some-future-status"}, {Status: "completed"}}
	f.completeScanTail()
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	if _, err := executeSync(t, context.Background(), "https://example.com"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if n := f.countRoute(rGetScan); n != 3 {
		t.Errorf("scan polls = %d, want 3 (unknown statuses keep polling)", n)
	}
}

func TestExecutePicksNewestResult(t *testing.T) {
	f := newFakeAcunetix(t)
	f.statuses = []*scanInfo{{Status: "completed", ScanSessionID: ""}}
	f.results = []scanResultItem{
		{ResultID: "res-old", StartDate: "2024-01-01"},
		{ResultID: "res-new", StartDate: "2024-05-01"},
	}
	f.vulnPages = []vulnerabilityListResponse{{Pagination: pagination{Cursors: []*string{nil, nil}}}}
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	if _, err := executeSync(t, context.Background(), "https://example.com"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if n := f.countPrefix(vulnRoute("res-new")); n != 1 {
		t.Errorf("newest result was not used; routes = %v", f.routesSnapshot())
	}
	if n := f.countPrefix(vulnRoute("res-old")); n != 0 {
		t.Errorf("stale result was used; routes = %v", f.routesSnapshot())
	}
}

func TestExecuteSingleResultUsed(t *testing.T) {
	f := newFakeAcunetix(t)
	f.statuses = []*scanInfo{{Status: "completed", ScanSessionID: ""}}
	f.results = []scanResultItem{{ResultID: "res-only", StartDate: "2024-01-01"}}
	f.vulnPages = []vulnerabilityListResponse{{Pagination: pagination{Cursors: []*string{nil, nil}}}}
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	if _, err := executeSync(t, context.Background(), "https://example.com"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if n := f.countPrefix(vulnRoute("res-only")); n != 1 {
		t.Errorf("single result was not used; routes = %v", f.routesSnapshot())
	}
}

func TestExecuteNoResultsHardError(t *testing.T) {
	f := newFakeAcunetix(t)
	f.statuses = []*scanInfo{{Status: "completed", ScanSessionID: ""}}
	// no results → hard error, no silent 0-finding path.
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	_, err := executeSync(t, context.Background(), "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "has no results") {
		t.Fatalf("err = %v, want 'has no results'", err)
	}
	assertNoDeletes(t, f)
}

func TestExecuteEmptyVulnerabilities(t *testing.T) {
	f := newFakeAcunetix(t)
	f.completeScanTail() // one empty page
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	findings, err := executeSync(t, context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
	if n := f.countPrefix(rDeleteTarget); n != 1 {
		t.Errorf("cleanup DELETE /targets = %d, want 1", n)
	}
}

func TestExecuteRepeatedCursorTerminates(t *testing.T) {
	f := newFakeAcunetix(t)
	f.completeScanTail()
	page := vulnerabilityListResponse{
		Vulnerabilities: []vulnerability{{VulnID: "v1", VTName: "x", Severity: 1}},
		Pagination:      pagination{Cursors: []*string{strptr("cur")}},
	}
	f.vulnPages = []vulnerabilityListResponse{page, page, page, page, page}
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	if _, err := executeSync(t, context.Background(), "https://example.com"); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	// The repeated cursor is seen once and never revisited: exactly 2 requests.
	if n := f.countRoute(rVulns); n != 2 {
		t.Errorf("vulnerability page requests = %d, want 2 (repeated cursor must terminate)", n)
	}
}

func TestExecuteDetail500StillEmits(t *testing.T) {
	f := newFakeAcunetix(t)
	f.completeScanTail()
	f.vulnPages = []vulnerabilityListResponse{{
		Vulnerabilities: []vulnerability{{VulnID: "vuln-a", VTName: "Still Emitted", Severity: 3, AffectsURL: "https://example.com/a"}},
		Pagination:      pagination{Cursors: []*string{nil, nil}},
	}}
	f.detailErr["vuln-a"] = http.StatusInternalServerError
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	findings, err := executeSync(t, context.Background(), "https://example.com")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(findings) != 1 || findings[0].Name != "Still Emitted" || findings[0].Severity != "high" {
		t.Fatalf("findings = %+v, want the list-data fallback finding", findings)
	}
	if n := f.countPrefix(rDeleteTarget); n != 1 {
		t.Errorf("cleanup DELETE /targets = %d, want 1", n)
	}
}

func TestExecuteCtxCancelMidPoll(t *testing.T) {
	f := newFakeAcunetix(t)
	f.statuses = []*scanInfo{{Status: "processing"}} // never terminal
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan connector.Finding, 16)
	done := make(chan error, 1)
	go func() {
		done <- (&AcunetixAdapter{}).Execute(ctx, map[string]any{"target": "https://example.com"}, out)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		if f.countPrefix(rGetScan) >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the first poll")
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Execute did not return after cancel")
	}
	if n := len(out); n != 0 {
		t.Errorf("emitted %d findings on cancel, want 0", n)
	}
	assertNoDeletes(t, f)
}

func TestExecuteScanAborted(t *testing.T) {
	f := newFakeAcunetix(t)
	f.statuses = []*scanInfo{{Status: "queued"}, {Status: "aborted"}}
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	_, err := executeSync(t, context.Background(), "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("err = %v, want aborted", err)
	}
	assertNoDeletes(t, f)
}

func TestExecuteScanFailed(t *testing.T) {
	f := newFakeAcunetix(t)
	f.statuses = []*scanInfo{{Status: "failed"}}
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	_, err := executeSync(t, context.Background(), "https://example.com")
	if err == nil || !strings.Contains(err.Error(), "failed") {
		t.Fatalf("err = %v, want failed", err)
	}
	assertNoDeletes(t, f)
}

func TestExecuteTargetCreate500(t *testing.T) {
	f := newFakeAcunetix(t)
	f.createTargetErr = http.StatusInternalServerError
	f.env(t, nil)
	shortenPoll(t, time.Millisecond)

	_, err := executeSync(t, context.Background(), "https://example.com")
	if err == nil {
		t.Fatal("want an error when target creation fails")
	}
	if n := f.countPrefix(rCreateScan); n != 0 {
		t.Errorf("POST /scans = %d, want 0", n)
	}
	assertNoDeletes(t, f)
}
