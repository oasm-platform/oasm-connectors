package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

// clearAcunetixEnv isolates each test from the ambient process env: OASM_CONFIG
// and every legacy ACUNETIX_* var are reset to empty (the loader treats empty
// as unset for required fields and as "use default" for the optional ones).
func clearAcunetixEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"OASM_CONFIG",
		"ACUNETIX_URL", "ACUNETIX_API_KEY", "ACUNETIX_PROFILE_ID",
		"ACUNETIX_CRITICALITY", "ACUNETIX_TARGET_DESCRIPTION",
		"ACUNETIX_INSECURE", "ACUNETIX_MAX_SCAN_TIME",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadAcunetixConfigOASMConfigFull(t *testing.T) {
	clearAcunetixEnv(t)
	t.Setenv("OASM_CONFIG", `{
		"url": "https://acunetix:3443",
		"apiKey": "secret-key",
		"profileId": "22222222-2222-2222-2222-222222222222",
		"criticality": 30,
		"targetDescription": "custom-desc",
		"disableTlsChecks": true,
		"maxScanTime": 3600
	}`)

	cfg, err := loadAcunetixConfig()
	if err != nil {
		t.Fatalf("loadAcunetixConfig: %v", err)
	}
	if cfg.URL != "https://acunetix:3443/api/v1" {
		t.Errorf("URL = %q, want normalized with /api/v1", cfg.URL)
	}
	if cfg.APIKey != "secret-key" {
		t.Errorf("APIKey = %q", cfg.APIKey)
	}
	if cfg.ProfileID != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("ProfileID = %q", cfg.ProfileID)
	}
	if cfg.Criticality != 30 {
		t.Errorf("Criticality = %d, want 30", cfg.Criticality)
	}
	if cfg.TargetDescription != "custom-desc" {
		t.Errorf("TargetDescription = %q", cfg.TargetDescription)
	}
	if !cfg.DisableTLSChecks {
		t.Errorf("DisableTLSChecks = false, want true")
	}
	if cfg.MaxScanTime != 3600 {
		t.Errorf("MaxScanTime = %d, want 3600", cfg.MaxScanTime)
	}
}

func TestLoadAcunetixConfigOASMConfigPartialDefaults(t *testing.T) {
	clearAcunetixEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://acunetix:3443","apiKey":"k"}`)

	cfg, err := loadAcunetixConfig()
	if err != nil {
		t.Fatalf("loadAcunetixConfig: %v", err)
	}
	if cfg.ProfileID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("ProfileID = %q, want the built-in Full Scan profile id", cfg.ProfileID)
	}
	if cfg.Criticality != 10 {
		t.Errorf("Criticality = %d, want 10", cfg.Criticality)
	}
	if cfg.TargetDescription != "oasm-scan" {
		t.Errorf("TargetDescription = %q, want oasm-scan", cfg.TargetDescription)
	}
	if cfg.MaxScanTime != 0 {
		t.Errorf("MaxScanTime = %d, want 0", cfg.MaxScanTime)
	}
	if cfg.DisableTLSChecks {
		t.Errorf("DisableTLSChecks = true, want false")
	}
}

func TestLoadAcunetixConfigOASMConfigMalformed(t *testing.T) {
	clearAcunetixEnv(t)
	t.Setenv("OASM_CONFIG", `{"url": "https://x"`)

	_, err := loadAcunetixConfig()
	if err == nil {
		t.Fatal("expected error for malformed OASM_CONFIG")
	}
	if !strings.Contains(err.Error(), "invalid OASM_CONFIG") {
		t.Errorf("err = %v, want invalid OASM_CONFIG", err)
	}
}

func TestLoadAcunetixConfigMissingURL(t *testing.T) {
	clearAcunetixEnv(t)
	t.Setenv("OASM_CONFIG", `{"apiKey":"k"}`)

	_, err := loadAcunetixConfig()
	if err == nil || !strings.Contains(err.Error(), "URL required") {
		t.Fatalf("err = %v, want URL required", err)
	}
}

func TestLoadAcunetixConfigMissingAPIKey(t *testing.T) {
	clearAcunetixEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://x"}`)

	_, err := loadAcunetixConfig()
	if err == nil || !strings.Contains(err.Error(), "API key required") {
		t.Fatalf("err = %v, want API key required", err)
	}
}

func TestLoadAcunetixConfigLegacyEnvFallback(t *testing.T) {
	clearAcunetixEnv(t)
	t.Setenv("ACUNETIX_URL", "https://legacy:3443/")
	t.Setenv("ACUNETIX_API_KEY", "legacy-key")
	t.Setenv("ACUNETIX_PROFILE_ID", "33333333-3333-3333-3333-333333333333")
	t.Setenv("ACUNETIX_CRITICALITY", "20")
	t.Setenv("ACUNETIX_TARGET_DESCRIPTION", "legacy-desc")
	t.Setenv("ACUNETIX_INSECURE", "true")
	t.Setenv("ACUNETIX_MAX_SCAN_TIME", "120")

	cfg, err := loadAcunetixConfig()
	if err != nil {
		t.Fatalf("loadAcunetixConfig: %v", err)
	}
	if cfg.URL != "https://legacy:3443/api/v1" {
		t.Errorf("URL = %q", cfg.URL)
	}
	if cfg.APIKey != "legacy-key" {
		t.Errorf("APIKey = %q", cfg.APIKey)
	}
	if cfg.ProfileID != "33333333-3333-3333-3333-333333333333" {
		t.Errorf("ProfileID = %q", cfg.ProfileID)
	}
	if cfg.Criticality != 20 {
		t.Errorf("Criticality = %d, want 20", cfg.Criticality)
	}
	if cfg.TargetDescription != "legacy-desc" {
		t.Errorf("TargetDescription = %q", cfg.TargetDescription)
	}
	if !cfg.DisableTLSChecks {
		t.Errorf("DisableTLSChecks = false, want true")
	}
	if cfg.MaxScanTime != 120 {
		t.Errorf("MaxScanTime = %d, want 120", cfg.MaxScanTime)
	}
}

func TestLoadAcunetixConfigInsecureTruthTable(t *testing.T) {
	cases := []struct {
		in      string
		want    bool
		wantErr bool
	}{
		{"true", true, false},
		{"1", true, false},
		{"T", true, false},
		{"false", false, false},
		{"0", false, false},
		{"F", false, false},
		{"banana", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			clearAcunetixEnv(t)
			t.Setenv("ACUNETIX_URL", "https://x")
			t.Setenv("ACUNETIX_API_KEY", "k")
			t.Setenv("ACUNETIX_INSECURE", tc.in)

			cfg, err := loadAcunetixConfig()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "invalid ACUNETIX_INSECURE") {
					t.Fatalf("err = %v, want invalid ACUNETIX_INSECURE", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadAcunetixConfig: %v", err)
			}
			if cfg.DisableTLSChecks != tc.want {
				t.Errorf("DisableTLSChecks = %v, want %v", cfg.DisableTLSChecks, tc.want)
			}
		})
	}
}

func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://h:3443", "https://h:3443/api/v1"},
		{"https://h:3443/", "https://h:3443/api/v1"},
		{"https://h:3443/api/v1", "https://h:3443/api/v1"},
		{"https://h:3443/api/v1/", "https://h:3443/api/v1"},
		{"  https://h:3443  ", "https://h:3443/api/v1"},
	}
	for _, tc := range cases {
		if got := normalizeBaseURL(tc.in); got != tc.want {
			t.Errorf("normalizeBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestCanonicalTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "https://example.com"},
		{"HTTPS://Example.COM/Path/", "https://example.com/Path"},
		{"https://example.com:443/", "https://example.com"},
		{"http://example.com:80/x", "http://example.com/x"},
		{"https://example.com:8443/x", "https://example.com:8443/x"},
		{"  https://example.com/a/b/  ", "https://example.com/a/b"},
	}
	for _, tc := range cases {
		if got := canonicalTarget(tc.in); got != tc.want {
			t.Errorf("canonicalTarget(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHostAndPath(t *testing.T) {
	cases := []struct {
		in, wantHost, wantPath string
	}{
		{"https://Example.com/Path/", "example.com", "/path"},
		{"https://example.com:443/x", "example.com", "/x"},
		{"http://example.com:80/x", "example.com", "/x"},
		{"https://example.com:8443/x", "example.com:8443", "/x"},
		{"https://example.com:8443", "example.com:8443", ""},
	}
	for _, tc := range cases {
		h, p := hostAndPath(tc.in)
		if h != tc.wantHost || p != tc.wantPath {
			t.Errorf("hostAndPath(%q) = (%q,%q), want (%q,%q)", tc.in, h, p, tc.wantHost, tc.wantPath)
		}
	}
}

func TestLastPathSegment(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://h/api/v1/targets/abc-123", "abc-123"},
		{"abc-123", "abc-123"},
		{"https://h/api/v1/targets/abc-123/", "abc-123"},
		{"https://h/api/v1/targets/abc-123?x=1", "abc-123"},
		{"https://h/api/v1/targets/abc-123#frag", "abc-123"},
	}
	for _, tc := range cases {
		if got := lastPathSegment(tc.in); got != tc.want {
			t.Errorf("lastPathSegment(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func strptr(s string) *string { return &s }

func TestCursorWalker(t *testing.T) {
	t.Run("null then next advances", func(t *testing.T) {
		w := &cursorWalker{seen: map[string]bool{}}
		got, ok := w.next([]*string{nil, strptr("next")}, "")
		if !ok || got != "next" {
			t.Fatalf("next = (%q,%v), want (next,true)", got, ok)
		}
	})

	t.Run("single cursor advances", func(t *testing.T) {
		w := &cursorWalker{seen: map[string]bool{}}
		got, ok := w.next([]*string{strptr("next")}, "")
		if !ok || got != "next" {
			t.Fatalf("next = (%q,%v), want (next,true)", got, ok)
		}
	})

	t.Run("first page two distinct cursors advances to first", func(t *testing.T) {
		w := &cursorWalker{seen: map[string]bool{}}
		got, ok := w.next([]*string{strptr("A"), strptr("B")}, "")
		if !ok || got != "A" {
			t.Fatalf("next = (%q,%v), want (A,true) — never skip first candidate", got, ok)
		}
		// follow-up response [A,B] with sent=A must advance to B
		got, ok = w.next([]*string{strptr("A"), strptr("B")}, "A")
		if !ok || got != "B" {
			t.Fatalf("next = (%q,%v), want (B,true)", got, ok)
		}
	})

	t.Run("all null stops", func(t *testing.T) {
		w := &cursorWalker{seen: map[string]bool{}}
		if got, ok := w.next([]*string{nil, nil}, ""); ok {
			t.Fatalf("next = (%q,%v), want stop", got, ok)
		}
	})

	t.Run("repeated cursor stops", func(t *testing.T) {
		w := &cursorWalker{seen: map[string]bool{}}
		if got, ok := w.next([]*string{strptr("cur"), strptr("cur")}, ""); !ok || got != "cur" {
			t.Fatalf("first next = (%q,%v), want (cur,true)", got, ok)
		}
		if got, ok := w.next([]*string{strptr("cur"), strptr("cur")}, "cur"); ok {
			t.Fatalf("second next = (%q,%v), want stop", got, ok)
		}
	})

	t.Run("already seen cursor stops", func(t *testing.T) {
		w := &cursorWalker{seen: map[string]bool{"x": true}}
		if got, ok := w.next([]*string{strptr("x")}, ""); ok {
			t.Fatalf("next = (%q,%v), want stop", got, ok)
		}
	})

	t.Run("maxPages cap stops", func(t *testing.T) {
		w := &cursorWalker{seen: map[string]bool{}, pages: maxPages}
		if got, ok := w.next([]*string{strptr("x")}, ""); ok {
			t.Fatalf("next = (%q,%v), want stop at cap", got, ok)
		}
	})
}

// paginateClient builds a client pointed at an httptest server with a recorded
// request log. It never asserts on X-Auth here — paginateAll exercises paths.
func paginateClient(t *testing.T, h http.HandlerFunc, calls *[]string, mu *sync.Mutex) (*acunetixClient, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	c := &acunetixClient{baseURL: srv.URL + "/api/v1", apiKey: "k", hc: srv.Client()}
	return c, srv.Close
}

func TestPaginateAllTwoPagesNoLimitParam(t *testing.T) {
	var mu sync.Mutex
	var calls []string

	c, closeSrv := paginateClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.URL.RawQuery)
		mu.Unlock()
		page := r.URL.Query().Get("c")
		w.Header().Set("Content-Type", "application/json")
		if page == "" {
			items := make([]target, 100)
			_ = json.NewEncoder(w).Encode(targetListResponse{
				Targets:    items,
				Pagination: pagination{Count: 150, Cursors: []*string{nil, strptr("c1")}},
			})
			return
		}
		items := make([]target, 50)
		_ = json.NewEncoder(w).Encode(targetListResponse{
			Targets:    items,
			Pagination: pagination{Count: 150, Cursors: []*string{strptr("c1"), nil}},
		})
	}, &calls, &mu)
	defer closeSrv()

	got, err := paginateAll(context.Background(), c, "/targets", func(raw []byte) ([]target, pagination, error) {
		var resp targetListResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, pagination{}, err
		}
		return resp.Targets, resp.Pagination, nil
	})
	if err != nil {
		t.Fatalf("paginateAll: %v", err)
	}
	if len(got) != 150 {
		t.Errorf("got %d items, want 150", len(got))
	}

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("requests = %d, want 2 (%v)", len(calls), calls)
	}
	for i, q := range calls {
		if strings.Contains(q, "l=") {
			t.Errorf("request %d sent l= param: %q (must be omitted)", i, q)
		}
	}
	if calls[0] != "" {
		t.Errorf("first request query = %q, want empty (no cursor)", calls[0])
	}
	if calls[1] != "c=c1" {
		t.Errorf("second request query = %q, want c=c1", calls[1])
	}
}

func TestPaginateAllIncompleteLoudError(t *testing.T) {
	c, closeSrv := paginateClient(t, func(w http.ResponseWriter, r *http.Request) {
		items := make([]target, 100)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(targetListResponse{
			Targets:    items,
			Pagination: pagination{Count: 150, Cursors: []*string{nil, nil}},
		})
	}, nil, nil)
	defer closeSrv()

	_, err := paginateAll(context.Background(), c, "/targets", func(raw []byte) ([]target, pagination, error) {
		var resp targetListResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, pagination{}, err
		}
		return resp.Targets, resp.Pagination, nil
	})
	if err == nil {
		t.Fatal("expected pagination incomplete error")
	}
	want := "acunetix: /targets pagination incomplete: got 100 of 150"
	if err.Error() != want {
		t.Errorf("err = %q, want %q", err.Error(), want)
	}
}

func TestErrorDecode(t *testing.T) {
	c, closeSrv := paginateClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"code":500,"reason":"boom","details":["x"]}`))
	}, nil, nil)
	defer closeSrv()

	_, err := c.getScan(context.Background(), "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, want := range []string{"500", "code=500", "boom", "[x]"} {
		if !strings.Contains(msg, want) {
			t.Errorf("err %q missing %q", msg, want)
		}
	}
}

func TestDoJSONEmptyBodyTolerated(t *testing.T) {
	c, closeSrv := paginateClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}, nil, nil)
	defer closeSrv()

	_, err := c.doJSON(context.Background(), http.MethodDelete, "/targets/abc", nil, nil)
	if err != nil {
		t.Fatalf("204 must be tolerated, got %v", err)
	}
}

func TestDoSetsXAuthAndContentType(t *testing.T) {
	var mu sync.Mutex
	var gotAuth, gotCT string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotAuth = r.Header.Get("X-Auth")
		gotCT = r.Header.Get("Content-Type")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		mu.Unlock()
		w.Header().Set("Location", "/api/v1/targets/created-1")
		_ = json.NewEncoder(w).Encode(target{TargetID: "created-1"})
	}))
	defer srv.Close()

	c := &acunetixClient{baseURL: srv.URL + "/api/v1", apiKey: "KEY123", hc: srv.Client()}
	id, err := c.createTarget(context.Background(), "https://example.com", "oasm-scan", 0)
	if err != nil {
		t.Fatalf("createTarget: %v", err)
	}
	if id != "created-1" {
		t.Errorf("id = %q", id)
	}
	if gotAuth != "KEY123" {
		t.Errorf("X-Auth = %q, want KEY123", gotAuth)
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if _, ok := gotBody["target_id"]; ok {
		t.Errorf("POST /targets body must NOT include target_id: %v", gotBody)
	}
	// criticality 0 must be transmitted (no omitempty)
	crit, ok := gotBody["criticality"]
	if !ok {
		t.Fatalf("criticality missing from body: %v", gotBody)
	}
	if n, _ := crit.(float64); n != 0 {
		t.Errorf("criticality = %v, want 0", crit)
	}
}

func TestCreateScanSendsNoUserAuthorizedToScan(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Location", "/api/v1/scans/scan-9")
	}))
	defer srv.Close()

	c := &acunetixClient{baseURL: srv.URL + "/api/v1", apiKey: "k", hc: srv.Client()}
	id, err := c.createScan(context.Background(), "t-1", defaultProfileID, 0)
	if err != nil {
		t.Fatalf("createScan: %v", err)
	}
	if id != "scan-9" {
		t.Errorf("scan id = %q, want scan-9", id)
	}
	if _, ok := body["user_authorized_to_scan"]; ok {
		t.Errorf("body must NOT contain user_authorized_to_scan: %v", body)
	}
	if body["target_id"] != "t-1" {
		t.Errorf("body target_id = %v, want t-1", body["target_id"])
	}
}

func TestCreateScanFallsBackToDecodedScanID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No Location header → must fall back to the decoded scan_id.
		_ = json.NewEncoder(w).Encode(scanItemResponse{ScanID: "decoded-id"})
	}))
	defer srv.Close()

	c := &acunetixClient{baseURL: srv.URL + "/api/v1", apiKey: "k", hc: srv.Client()}
	id, err := c.createScan(context.Background(), "t-1", defaultProfileID, 0)
	if err != nil {
		t.Fatalf("createScan: %v", err)
	}
	if id != "decoded-id" {
		t.Errorf("scan id = %q, want decoded-id", id)
	}
}

func TestFindTargetByAddress(t *testing.T) {
	t.Run("exact canonical match", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(targetListResponse{
				Targets:    []target{{TargetID: "t1", Address: "https://example.com/path"}},
				Pagination: pagination{Cursors: []*string{nil, nil}},
			})
		}))
		defer srv.Close()
		c := &acunetixClient{baseURL: srv.URL + "/api/v1", apiKey: "k", hc: srv.Client()}

		id, ok, err := c.findTargetByAddress(context.Background(), "https://Example.com/path/")
		if err != nil || !ok || id != "t1" {
			t.Fatalf("got (%q,%v,%v), want (t1,true,nil)", id, ok, err)
		}
	})

	t.Run("second pass requires host and path", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(targetListResponse{
				Targets:    []target{{TargetID: "t1", Address: "http://example.com/a/b"}},
				Pagination: pagination{Cursors: []*string{nil, nil}},
			})
		}))
		defer srv.Close()
		c := &acunetixClient{baseURL: srv.URL + "/api/v1", apiKey: "k", hc: srv.Client()}

		// scheme differs, path matches → second pass matches
		id, ok, err := c.findTargetByAddress(context.Background(), "https://example.com/a/b")
		if err != nil || !ok || id != "t1" {
			t.Fatalf("got (%q,%v,%v), want (t1,true,nil)", id, ok, err)
		}
	})

	t.Run("different path never matches", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(targetListResponse{
				Targets:    []target{{TargetID: "t1", Address: "https://example.com/other"}},
				Pagination: pagination{Cursors: []*string{nil, nil}},
			})
		}))
		defer srv.Close()
		c := &acunetixClient{baseURL: srv.URL + "/api/v1", apiKey: "k", hc: srv.Client()}

		id, ok, err := c.findTargetByAddress(context.Background(), "https://example.com/wanted")
		if err != nil || ok || id != "" {
			t.Fatalf("got (%q,%v,%v), want (\"\",false,nil)", id, ok, err)
		}
	})
}

// sanity: url.QueryEscape is what paginateAll uses; assert the encoding is
// applied so a cursor with reserved characters round-trips.
func TestPaginateAllEscapesCursor(t *testing.T) {
	var gotCursor string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCursor = r.URL.Query().Get("c")
		_ = json.NewEncoder(w).Encode(targetListResponse{
			Targets:    nil,
			Pagination: pagination{Cursors: []*string{nil, nil}},
		})
	}))
	defer srv.Close()
	c := &acunetixClient{baseURL: srv.URL + "/api/v1", apiKey: "k", hc: srv.Client()}

	w := &cursorWalker{seen: map[string]bool{}}
	cur, ok := w.next([]*string{strptr("a b&c")}, "")
	if !ok {
		t.Fatal("expected a cursor")
	}
	if _, _, err := c.do(context.Background(), http.MethodGet, "/targets?c="+url.QueryEscape(cur), nil); err != nil {
		t.Fatalf("do: %v", err)
	}
	if gotCursor != "a b&c" {
		t.Errorf("decoded cursor = %q, want %q", gotCursor, "a b&c")
	}
}
