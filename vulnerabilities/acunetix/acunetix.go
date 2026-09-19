package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// defaultProfileID is the built-in "Full Scan" profile. A profile id is
// required to create a scan; when the operator does not set one we use the
// scanner's well-known full-scan profile instead of failing the job.
const defaultProfileID = "11111111-1111-1111-1111-111111111111"

// acunetixConfig holds the Acunetix connection + scan settings.
type acunetixConfig struct {
	URL               string
	APIKey            string
	ProfileID         string
	Criticality       int
	TargetDescription string
	DisableTLSChecks  bool
	MaxScanTime       int
}

// configProfile is the OASM_CONFIG JSON shape the Worker ships per job.
// Keys are camelCase to mirror manifest.yaml configSchema.
type configProfile struct {
	URL               string `json:"url"`
	APIKey            string `json:"apiKey"`
	ProfileID         string `json:"profileId"`
	Criticality       *int   `json:"criticality"`
	TargetDescription string `json:"targetDescription"`
	DisableTLSChecks  bool   `json:"disableTlsChecks"`
	MaxScanTime       *int   `json:"maxScanTime"`
}

// loadAcunetixConfig reads the Acunetix connection + scan settings. The primary
// source is OASM_CONFIG (the per-job config profile) — the SDK runtime
// overrides that env var per execution so a warm-pool reused container sees
// its own job's config rather than its first-run env. ACUNETIX_* env vars
// remain as a legacy fallback for direct-runtime use. URL and API key are
// required; the rest fall back to sane defaults.
func loadAcunetixConfig() (*acunetixConfig, error) {
	cfg := &acunetixConfig{}

	if raw := strings.TrimSpace(os.Getenv("OASM_CONFIG")); raw != "" {
		var p configProfile
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
		}
		cfg.URL = p.URL
		cfg.APIKey = p.APIKey
		cfg.ProfileID = p.ProfileID
		cfg.TargetDescription = p.TargetDescription
		cfg.DisableTLSChecks = p.DisableTLSChecks
		cfg.Criticality = 10
		if p.Criticality != nil {
			cfg.Criticality = *p.Criticality
		}
		if p.MaxScanTime != nil {
			cfg.MaxScanTime = *p.MaxScanTime
		}
	} else {
		cfg.URL = os.Getenv("ACUNETIX_URL")
		cfg.APIKey = os.Getenv("ACUNETIX_API_KEY")
		cfg.ProfileID = os.Getenv("ACUNETIX_PROFILE_ID")
		cfg.TargetDescription = os.Getenv("ACUNETIX_TARGET_DESCRIPTION")
		cfg.Criticality = 10

		if raw := strings.TrimSpace(os.Getenv("ACUNETIX_INSECURE")); raw != "" {
			v, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid ACUNETIX_INSECURE: %w", err)
			}
			cfg.DisableTLSChecks = v
		}
		if raw := strings.TrimSpace(os.Getenv("ACUNETIX_CRITICALITY")); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid %s: %w", "ACUNETIX_CRITICALITY", err)
			}
			cfg.Criticality = v
		}
		if raw := strings.TrimSpace(os.Getenv("ACUNETIX_MAX_SCAN_TIME")); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid %s: %w", "ACUNETIX_MAX_SCAN_TIME", err)
			}
			cfg.MaxScanTime = v
		}
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("acunetix URL required (config.url or ACUNETIX_URL)")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("acunetix API key required (config.apiKey or ACUNETIX_API_KEY)")
	}

	if cfg.ProfileID == "" {
		cfg.ProfileID = defaultProfileID
	}
	if cfg.TargetDescription == "" {
		cfg.TargetDescription = "oasm-scan"
	}
	cfg.URL = normalizeBaseURL(cfg.URL)

	return cfg, nil
}

// normalizeBaseURL trims whitespace and any trailing slash, then appends the
// API version segment when it is absent.
func normalizeBaseURL(raw string) string {
	s := strings.TrimRight(strings.TrimSpace(raw), "/")
	if !strings.HasSuffix(s, "/api/v1") {
		s += "/api/v1"
	}
	return s
}

// canonicalTarget produces a comparable form of a target address: lower-cased
// host, default port stripped, trailing slashes removed. It is the exact-match
// key for the first findTargetByAddress pass.
func canonicalTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return strings.TrimSpace(raw)
	}
	host := strings.ToLower(u.Host)
	if u.Scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	} else if u.Scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}
	return strings.TrimRight(u.Scheme+"://"+host+u.Path, "/")
}

// hostAndPath returns the lower-cased host and path of a target address. The
// default port for the address's scheme is the ONLY port stripped — a
// non-default port such as :8443 is preserved so a different-port target is
// never matched. Used only for the strict second-pass target match (same host
// AND same path), so it deliberately avoids u.Hostname() (which strips every
// port).
func hostAndPath(raw string) (host, path string) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", ""
	}
	host = strings.ToLower(u.Host)
	if u.Scheme == "https" {
		host = strings.TrimSuffix(host, ":443")
	} else if u.Scheme == "http" {
		host = strings.TrimSuffix(host, ":80")
	}
	path = strings.ToLower(strings.TrimRight(u.EscapedPath(), "/"))
	return host, path
}

// ---------------------------------------------------------------------------
// DTOs — exact JSON tags per the API spec (doc:4001-4033, :3939-3954,
// :4224-4314, :4315-4351, :5885-5921, :4843-4854, :4718-4841, :5648-5663).
// ---------------------------------------------------------------------------

// target is the Target resource. TargetID carries omitempty so a POST /targets
// body never serializes the read-only id, while Criticality has NO omitempty so
// the valid value 0 (Low) is transmitted rather than silently dropped.
type target struct {
	TargetID    string `json:"target_id,omitempty"`
	Address     string `json:"address"`
	Description string `json:"description,omitempty"`
	Criticality int    `json:"criticality"`
}

type targetListResponse struct {
	Targets    []target   `json:"targets"`
	Pagination pagination `json:"pagination"`
}

type pagination struct {
	Count      int       `json:"count"`
	Cursors    []*string `json:"cursors"`
	CursorHash string    `json:"cursor_hash,omitempty"`
	Sort       string    `json:"sort,omitempty"`
}

// scanBody is the POST /scans request. It carries only the fields the spec
// defines for the "run immediately" body (doc:2082).
type scanBody struct {
	TargetID    string   `json:"target_id"`
	ProfileID   string   `json:"profile_id"`
	Schedule    schedule `json:"schedule"`
	MaxScanTime int      `json:"max_scan_time,omitempty"`
}

type schedule struct {
	Disable       bool    `json:"disable"`
	StartDate     *string `json:"start_date"`
	TimeSensitive bool    `json:"time_sensitive"`
}

type scanItemResponse struct {
	ScanID         string    `json:"scan_id"`
	CurrentSession *scanInfo `json:"current_session"`
	Target         *target   `json:"target"`
}

type scanInfo struct {
	Status        string `json:"status"`
	Progress      int    `json:"progress"`
	ScanSessionID string `json:"scan_session_id"`
	StartDate     string `json:"start_date"`
}

type scanResultListResponse struct {
	Results    []scanResultItem `json:"results"`
	Pagination pagination       `json:"pagination"`
}

type scanResultItem struct {
	ScanID    string `json:"scan_id"`
	ResultID  string `json:"result_id"`
	StartDate string `json:"start_date"`
	EndDate   string `json:"end_date"`
	Status    string `json:"status"`
}

type vulnerabilityListResponse struct {
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
	Pagination      pagination      `json:"pagination"`
}

type vulnerability struct {
	VulnID        string   `json:"vuln_id"`
	VTName        string   `json:"vt_name"`
	VTID          string   `json:"vt_id"`
	Severity      int      `json:"severity"`
	Criticality   int      `json:"criticality"`
	Tags          []string `json:"tags"`
	AffectsURL    string   `json:"affects_url"`
	AffectsDetail string   `json:"affects_detail"`
	TargetID      string   `json:"target_id"`
	LastSeen      string   `json:"last_seen"`
	Confidence    int      `json:"confidence"`
	Status        string   `json:"status"`
}

// vulnerabilityDetails embeds vulnerability anonymously so the base JSON keys
// are promoted, then adds the detail-only fields.
type vulnerabilityDetails struct {
	vulnerability
	Description     string  `json:"description"`
	Recommendation  string  `json:"recommendation"`
	LongDescription string  `json:"long_description"`
	Impact          string  `json:"impact"`
	Details         string  `json:"details"`
	CVSS2           string  `json:"cvss2"`
	CVSS3           string  `json:"cvss3"`
	CVSS4           string  `json:"cvss4"`
	CVSSScore       float64 `json:"cvss_score"`
	CVSS4Score      float64 `json:"cvss4_score"`
	References      []link  `json:"references"`
}

type link struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

type errorResponse struct {
	Code    int      `json:"code"`
	Reason  string   `json:"reason"`
	Details []string `json:"details"`
}

// ---------------------------------------------------------------------------
// HTTP client
// ---------------------------------------------------------------------------

type acunetixClient struct {
	baseURL string
	apiKey  string
	hc      *http.Client
}

// newAcunetixClient builds a client that authenticates every request with the
// API key (X-Auth header). The api key is never logged.
func newAcunetixClient(cfg *acunetixConfig) *acunetixClient {
	return &acunetixClient{
		baseURL: normalizeBaseURL(cfg.URL),
		apiKey:  cfg.APIKey,
		hc: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.DisableTLSChecks},
			},
		},
	}
}

// ponytail: no retries/backoff — a transient Acunetix 5xx fails the job. Ceiling:
// single attempt. Upgrade path: wrap do() with a bounded retry on 429/5xx.
//
// do performs one request against baseURL+path, returning the Location header
// and the raw body. It sets X-Auth on every request. On status >= 300 it
// decodes the ErrorDescriptionResponse and returns a loud error.
func (c *acunetixClient) do(ctx context.Context, method, path string, body any) (location string, raw []byte, err error) {
	var bodyReader io.Reader
	if body != nil {
		b, merr := json.Marshal(body)
		if merr != nil {
			return "", nil, fmt.Errorf("acunetix: marshal %s %s: %w", method, path, merr)
		}
		bodyReader = strings.NewReader(string(b))
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return "", nil, fmt.Errorf("acunetix: %s %s: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Auth", c.apiKey)

	resp, err := c.hc.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("acunetix: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	raw, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		return "", nil, fmt.Errorf("acunetix: %s %s: read body: %w", method, path, rerr)
	}

	if resp.StatusCode >= 300 {
		var er errorResponse
		if jerr := json.Unmarshal(raw, &er); jerr == nil && (er.Reason != "" || er.Code != 0) {
			return resp.Header.Get("Location"), raw, fmt.Errorf(
				"acunetix: %s %s: %s: code=%d reason=%s details=%v",
				method, path, resp.Status, er.Code, er.Reason, er.Details)
		}
		snippet := strings.TrimSpace(string(raw))
		if len(snippet) > 200 {
			snippet = snippet[:200]
		}
		return resp.Header.Get("Location"), raw, fmt.Errorf(
			"acunetix: %s %s: %s: %s", method, path, resp.Status, snippet)
	}

	return resp.Header.Get("Location"), raw, nil
}

// doJSON calls do and decodes a non-empty JSON body into out.
func (c *acunetixClient) doJSON(ctx context.Context, method, path string, body any, out any) (location string, err error) {
	location, raw, err := c.do(ctx, method, path, body)
	if err != nil {
		return location, err
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return location, fmt.Errorf("acunetix: decode %s %s: %w", method, path, err)
		}
	}
	return location, nil
}

// lastPathSegment returns the final path segment of a URL (query/fragment and
// trailing slashes stripped). Used to parse ids out of Location headers.
func lastPathSegment(raw string) string {
	if i := strings.IndexAny(raw, "?#"); i >= 0 {
		raw = raw[:i]
	}
	raw = strings.TrimRight(raw, "/")
	if i := strings.LastIndex(raw, "/"); i >= 0 {
		return raw[i+1:]
	}
	return raw
}

// ---------------------------------------------------------------------------
// Pagination
// ---------------------------------------------------------------------------

const maxPages = 1000 // hard safety cap; cursor exhaustion is the primary stop

type cursorWalker struct {
	seen  map[string]bool
	pages int
}

// next returns the next page cursor given the response cursors and the cursor
// that produced the current page ("" for the first page).
//
// It returns the FIRST non-nil, non-empty cursor that differs from the cursor
// just sent and has not been visited. It NEVER skips a candidate, so no page
// can be skipped. The spec describes cursors only as "cursor, current and
// known following cursors" (doc:3939-3954), so if a first-page response leads
// with the page's own "current" cursor, that page is fetched once more under
// that cursor; seen then prevents any further repeat, and duplicate findings
// are removed by dedupeVulnerabilities. The incompleteness error below is the
// loud guard against UNDER-fetch; over-fetch is bounded (one page) and deduped.
func (w *cursorWalker) next(cursors []*string, sent string) (string, bool) {
	if w.pages >= maxPages {
		return "", false
	}
	for _, c := range cursors {
		if c == nil || *c == "" || *c == sent || w.seen[*c] {
			continue
		}
		w.seen[*c] = true
		w.pages++
		return *c, true
	}
	return "", false
}

// paginateAll GETs path, following cursors until they are exhausted, and
// returns every item. The l parameter is deliberately OMITTED: the spec says
// the accepted limit range is 1 < l < 100 with default and maximum 100
// (doc:6792-6803), so l=100 is out of range — the server's default of 100
// items per page is used instead. It FAILS LOUDLY when the server reports
// (pagination.count > 0) more elements than were fetched, so pagination can
// never silently truncate findings.
func paginateAll[T any](
	ctx context.Context,
	c *acunetixClient,
	path string,
	decode func(raw []byte) (items []T, p pagination, err error),
) ([]T, error) {
	walker := &cursorWalker{seen: map[string]bool{}}
	var all []T
	cursor := ""
	for {
		reqPath := path
		if cursor != "" {
			reqPath += "?c=" + url.QueryEscape(cursor)
		}
		_, raw, err := c.do(ctx, http.MethodGet, reqPath, nil)
		if err != nil {
			return nil, err
		}
		items, p, err := decode(raw)
		if err != nil {
			return nil, fmt.Errorf("acunetix: decode %s: %w", path, err)
		}
		all = append(all, items...)
		next, ok := walker.next(p.Cursors, cursor)
		if !ok {
			if p.Count > 0 && len(all) < p.Count {
				return nil, fmt.Errorf("acunetix: %s pagination incomplete: got %d of %d", path, len(all), p.Count)
			}
			return all, nil
		}
		cursor = next
	}
}

// ---------------------------------------------------------------------------
// Client methods
// ---------------------------------------------------------------------------

// findTargetByAddress returns the id of a target whose address matches. The
// first pass is an exact canonicalTarget comparison; the second, stricter pass
// requires BOTH host AND path to agree (tolerating only scheme, default-port,
// trailing-slash and case differences). It NEVER deletes anything.
func (c *acunetixClient) findTargetByAddress(ctx context.Context, address string) (string, bool, error) {
	targets, err := paginateAll(ctx, c, "/targets", func(raw []byte) ([]target, pagination, error) {
		var resp targetListResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, pagination{}, err
		}
		return resp.Targets, resp.Pagination, nil
	})
	if err != nil {
		return "", false, err
	}

	want := canonicalTarget(address)
	for _, t := range targets {
		if canonicalTarget(t.Address) == want {
			return t.TargetID, true, nil
		}
	}

	wantHost, wantPath := hostAndPath(address)
	for _, t := range targets {
		h, p := hostAndPath(t.Address)
		if h != "" && h == wantHost && p == wantPath {
			log.Printf("acunetix: reusing target %s for %s", t.Address, address)
			return t.TargetID, true, nil
		}
	}

	return "", false, nil
}

// createTarget POSTs a new target. The target_id field is omitted from the
// request body (it is read-only); the created id is decoded from the response,
// falling back to the Location header.
func (c *acunetixClient) createTarget(ctx context.Context, address, description string, criticality int) (string, error) {
	var created target
	location, err := c.doJSON(ctx, http.MethodPost, "/targets", target{
		Address:     address,
		Description: description,
		Criticality: criticality,
	}, &created)
	if err != nil {
		return "", err
	}
	if created.TargetID != "" {
		return created.TargetID, nil
	}
	if id := lastPathSegment(location); id != "" {
		return id, nil
	}
	return "", fmt.Errorf("acunetix: create target returned no id")
}

// createScan creates a scan for a target and returns the scan id (from the
// Location header, falling back to the decoded ScanID).
func (c *acunetixClient) createScan(ctx context.Context, targetID, profileID string, maxScanTime int) (string, error) {
	var resp scanItemResponse
	location, err := c.doJSON(ctx, http.MethodPost, "/scans", scanBody{
		TargetID:    targetID,
		ProfileID:   profileID,
		Schedule:    schedule{Disable: false, StartDate: nil, TimeSensitive: false},
		MaxScanTime: maxScanTime,
	}, &resp)
	if err != nil {
		return "", err
	}
	if id := lastPathSegment(location); id != "" {
		return id, nil
	}
	if resp.ScanID != "" {
		return resp.ScanID, nil
	}
	return "", fmt.Errorf("acunetix: create scan returned no id")
}

func (c *acunetixClient) getScan(ctx context.Context, scanID string) (*scanItemResponse, error) {
	var resp scanItemResponse
	if _, err := c.doJSON(ctx, http.MethodGet, "/scans/"+url.PathEscape(scanID), nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *acunetixClient) getScanResults(ctx context.Context, scanID string) ([]scanResultItem, error) {
	return paginateAll(ctx, c, "/scans/"+url.PathEscape(scanID)+"/results", func(raw []byte) ([]scanResultItem, pagination, error) {
		var resp scanResultListResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, pagination{}, err
		}
		return resp.Results, resp.Pagination, nil
	})
}

func (c *acunetixClient) listVulnerabilities(ctx context.Context, scanID, resultID string) ([]vulnerability, error) {
	path := "/scans/" + url.PathEscape(scanID) + "/results/" + url.PathEscape(resultID) + "/vulnerabilities"
	return paginateAll(ctx, c, path, func(raw []byte) ([]vulnerability, pagination, error) {
		var resp vulnerabilityListResponse
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, pagination{}, err
		}
		return resp.Vulnerabilities, resp.Pagination, nil
	})
}

func (c *acunetixClient) getVulnerability(ctx context.Context, scanID, resultID, vulnID string) (*vulnerabilityDetails, error) {
	path := "/scans/" + url.PathEscape(scanID) + "/results/" + url.PathEscape(resultID) + "/vulnerabilities/" + url.PathEscape(vulnID)
	var resp vulnerabilityDetails
	if _, err := c.doJSON(ctx, http.MethodGet, path, nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *acunetixClient) deleteScan(ctx context.Context, scanID string) error {
	_, err := c.doJSON(ctx, http.MethodDelete, "/scans/"+url.PathEscape(scanID), nil, nil)
	return err
}

func (c *acunetixClient) deleteTarget(ctx context.Context, targetID string) error {
	_, err := c.doJSON(ctx, http.MethodDelete, "/targets/"+url.PathEscape(targetID), nil, nil)
	return err
}
