package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/oasm-platform/oasm-connectors/sdk/gitrepo"
)

// sampleReport is real `trivy fs` 0.75.0 output for a repository with a
// vulnerable npm lockfile, a root Dockerfile and committed AWS keys,
// trimmed to a few entries.
func sampleReport(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("testdata/report.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// fake records what the adapter did: the scan's args, every trivy call and
// every lock taken.
type fake struct {
	checkout string
	cache    string
	scanArgs []string
	calls    []string // "download:<flag> TMPDIR=…" or "scan"
	locks    []string // "exclusive" / "shared"
	// downloadErr fails the DB downloads; lockErr fails the exclusive lock.
	downloadErr error
	lockErr     error
}

// fakeAdapter wires a checkout dir, a cache dir and a trivy run that "downloads"
// a DB by writing its metadata.json and "scans" by writing `report` to the
// --output path. A non-nil runErr fails the scan.
func fakeAdapter(t *testing.T, report string, runErr error) (TrivyAdapter, *fake) {
	t.Helper()
	f := &fake{checkout: t.TempDir(), cache: t.TempDir()}
	a := TrivyAdapter{
		cacheDir: f.cache,
		clone: func(_ context.Context, _ gitrepo.Inputs, opts gitrepo.Options) (*gitrepo.Checkout, error) {
			if opts.Depth != 1 {
				t.Fatalf("clone depth = %d, want 1", opts.Depth)
			}
			return &gitrepo.Checkout{Dir: f.checkout, Commit: "c0ffee"}, nil
		},
		lock: func(ctx context.Context, path string, exclusive bool, _ time.Duration) (func(), error) {
			if filepath.Dir(path) != f.cache {
				t.Fatalf("lock %q outside the cache dir", path)
			}
			if exclusive {
				f.locks = append(f.locks, "exclusive")
				if f.lockErr != nil {
					return nil, f.lockErr
				}
			} else {
				f.locks = append(f.locks, "shared")
			}
			return func() {}, ctx.Err()
		},
		run: func(_ context.Context, args, env []string) (string, error) {
			for _, db := range []trivyDB{vulnDB, javaDB} {
				if slices.Contains(args, db.flag) {
					f.calls = append(f.calls, "download:"+db.flag+" "+strings.Join(env, " "))
					if f.downloadErr != nil {
						return "FATAL mirror unreachable", f.downloadErr
					}
					writeMetadata(t, f.cache, db)
					return "", nil
				}
			}
			f.calls = append(f.calls, "scan")
			f.scanArgs = args
			if runErr != nil {
				return "INFO noise\nFATAL scan exploded", runErr
			}
			i := slices.Index(args, "--output")
			if err := os.WriteFile(args[i+1], []byte(report), 0o600); err != nil {
				t.Fatal(err)
			}
			return "", nil
		},
	}
	return a, f
}

func writeMetadata(t *testing.T, cache string, db trivyDB) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(cache, db.dir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, db.dir, "metadata.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func collect(t *testing.T, a TrivyAdapter, ctx context.Context, inputs map[string]any) ([]connector.Finding, error) {
	t.Helper()
	out := make(chan connector.Finding, 32)
	err := a.Execute(ctx, inputs, out)
	close(out)
	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

var validInputs = map[string]any{"repository": "https://github.com/acme/web", "ref": "main"}

func byName(findings []connector.Finding) map[string]connector.Finding {
	m := make(map[string]connector.Finding, len(findings))
	for _, f := range findings {
		m[f.Name] = f
	}
	return m
}

func TestExecuteMapsVulnerabilities(t *testing.T) {
	a, f := fakeAdapter(t, sampleReport(t), nil)

	findings, err := collect(t, a, context.Background(), validInputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 6 {
		t.Fatalf("want 6 findings (2 vuln, 2 misconfig, 2 secret), got %d", len(findings))
	}
	for _, f := range findings {
		if err := f.Validate(); err != nil {
			t.Fatalf("finding %q must be transportable: %v", f.Name, err)
		}
		if f.Commit != "c0ffee" {
			t.Fatalf("finding %q not stamped with the scanned commit: %q", f.Name, f.Commit)
		}
	}

	m := byName(findings)
	cve, ok := m["CVE-2020-8203 in lodash"]
	if !ok {
		t.Fatalf("CVE finding missing: %v", m)
	}
	if cve.Severity != "high" || cve.PackageName != "lodash" || cve.InstalledVersion != "4.17.15" || cve.FixedVersion != "4.17.19" {
		t.Fatalf("package fields not mapped: %+v", cve)
	}
	if cve.FilePath != "web/package-lock.json" || cve.LineStart != 1 || cve.LineEnd != 1 {
		t.Fatalf("location not mapped from package Locations: %+v", cve)
	}
	if cve.Fingerprint != "CVE-2020-8203:web/package-lock.json:lodash@4.17.15" {
		t.Fatalf("fingerprint = %q", cve.Fingerprint)
	}
	if len(cve.CVEID) != 1 || cve.CVEID[0] != "CVE-2020-8203" {
		t.Fatalf("CVEID = %v", cve.CVEID)
	}
	// Severity came from GHSA, so its CVSS wins.
	if cve.CVSSScore != 7.4 || !strings.HasPrefix(cve.CVSSMetrics, "CVSS:3.1/") {
		t.Fatalf("CVSS = %v %q", cve.CVSSScore, cve.CVSSMetrics)
	}
	if strings.Join(cve.CWEID, ",") != "CWE-1321,CWE-770" {
		t.Fatalf("CWEID = %v", cve.CWEID)
	}
	if cve.PublicationDate.IsZero() || cve.ModificationDate.IsZero() {
		t.Fatalf("dates not mapped: %+v", cve)
	}
	if !strings.Contains(cve.Solution, "4.17.19") {
		t.Fatalf("solution should name the fixed version: %q", cve.Solution)
	}

	// Non-CVE advisories carry no CVE ID and no dates, but still transport.
	nswg := m["NSWG-ECO-516 in lodash"]
	if len(nswg.CVEID) != 0 || !nswg.PublicationDate.IsZero() {
		t.Fatalf("non-CVE advisory mis-mapped: %+v", nswg)
	}

	joined := strings.Join(f.scanArgs, " ")
	for _, want := range []string{"fs ", "--format json", "--scanners vuln,misconfig", "--exit-code 0", "--disable-telemetry", "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--cache-dir " + f.cache} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args %q missing %q", joined, want)
		}
	}
}

func TestExecuteMapsMisconfigurations(t *testing.T) {
	a, _ := fakeAdapter(t, sampleReport(t), nil)
	findings, err := collect(t, a, context.Background(), validInputs)
	if err != nil {
		t.Fatal(err)
	}
	m := byName(findings)

	withLine, ok := m["DS-0025: 'apk add' is missing '--no-cache'"]
	if !ok {
		t.Fatalf("DS-0025 missing: %v", m)
	}
	if withLine.FilePath != "Dockerfile" || withLine.LineStart != 2 || withLine.LineEnd != 2 {
		t.Fatalf("misconfig location: %+v", withLine)
	}
	if withLine.Fingerprint != "DS-0025:Dockerfile:2" || withLine.Solution == "" {
		t.Fatalf("misconfig fingerprint/solution: %+v", withLine)
	}

	noLine := m["DS-0002: Image user should not be 'root'"]
	if noLine.Severity != "high" || noLine.LineStart != 0 || noLine.Fingerprint != "DS-0002:Dockerfile:0" {
		t.Fatalf("file-level misconfig: %+v", noLine)
	}
}

func TestExecuteNeverForwardsSecretValues(t *testing.T) {
	a, _ := fakeAdapter(t, sampleReport(t), nil)
	findings, err := collect(t, a, context.Background(), validInputs)
	if err != nil {
		t.Fatal(err)
	}
	secret, ok := byName(findings)["Leaked secret: aws-access-key-id"]
	if !ok || secret.Severity != "critical" || secret.FilePath != "creds.ini" || secret.LineStart != 1 {
		t.Fatalf("secret not mapped: %+v", secret)
	}
	for _, f := range findings {
		blob := strings.Join([]string{f.Name, f.Description, f.Solution, f.MatchedAt}, " ")
		if strings.Contains(blob, "****") || strings.Contains(blob, "aws_access_key_id =") {
			t.Fatalf("report Match/Code leaked into the finding: %+v", f)
		}
	}
}

func TestBuildArgsFromProfile(t *testing.T) {
	cfg := &trivyConfig{
		Scanners:      []string{"vuln", "secret"},
		Severity:      []string{"High", "critical", "info"},
		IgnoreUnfixed: true,
		SkipDirs:      []string{"testdata", "-weird", " "},
	}
	args, err := buildArgs(cfg, "/repo", "/r.json", "/cache")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"--scanners vuln,secret", "--severity HIGH,CRITICAL,UNKNOWN", "--ignore-unfixed", "--skip-dirs=testdata", "--skip-dirs=-weird"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args %q missing %q", joined, want)
		}
	}
	if strings.Count(joined, "--skip-dirs") != 2 {
		t.Fatalf("blank skipDirs must be dropped: %q", joined)
	}
	if args[len(args)-1] != "/repo" {
		t.Fatalf("scanned dir must be the last arg: %q", joined)
	}
}

func TestBadProfileIsFatal(t *testing.T) {
	for _, raw := range []string{`{"scanners":["license"]}`, `{"severity":["urgent"]}`} {
		ctx := connector.WithConfig(context.Background(), raw)
		a, f := fakeAdapter(t, "", nil)
		if err := a.Validate(ctx, validInputs); err == nil || !strings.HasPrefix(err.Error(), "fatal:") {
			t.Fatalf("Validate(%s) = %v, want fatal error", raw, err)
		}
		if _, err := collect(t, a, ctx, validInputs); err == nil {
			t.Fatalf("Execute(%s) must fail", raw)
		}
		if len(f.calls) != 0 {
			t.Fatalf("trivy must not run with a bad profile %s", raw)
		}
	}
}

func TestExecuteNothingFound(t *testing.T) {
	for _, report := range []string{"", `{"SchemaVersion":2,"Results":[]}`, `{"SchemaVersion":2}`} {
		a, _ := fakeAdapter(t, report, nil)
		findings, err := collect(t, a, context.Background(), validInputs)
		if err != nil || len(findings) != 0 {
			t.Fatalf("report %q: want no findings and no error, got %d / %v", report, len(findings), err)
		}
	}
}

func TestExecuteToolFailureKeepsStderrTail(t *testing.T) {
	a, _ := fakeAdapter(t, "", errors.New("exit status 1"))
	_, err := collect(t, a, context.Background(), validInputs)
	if err == nil || !strings.Contains(err.Error(), "scan exploded") {
		t.Fatalf("want tool failure with stderr tail, got %v", err)
	}
}

func TestExecuteRejectsUnsafeInputs(t *testing.T) {
	a, _ := fakeAdapter(t, "", nil)
	if _, err := collect(t, a, context.Background(), map[string]any{"repository": "file:///etc"}); err == nil {
		t.Fatal("want an error for a file:// repository")
	}
	if err := a.Validate(context.Background(), map[string]any{}); err == nil {
		t.Fatal("Validate must reject missing repository")
	}
}

func TestExecuteStopsOnCancel(t *testing.T) {
	a, _ := fakeAdapter(t, sampleReport(t), nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := make(chan connector.Finding) // unbuffered: nothing ever reads it
	if err := a.Execute(ctx, validInputs, out); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestParseReportRejectsGarbage(t *testing.T) {
	if _, err := parseReport([]byte("not json"), ""); err == nil {
		t.Fatal("want an error for a malformed report")
	}
}

func TestSeverityFor(t *testing.T) {
	for in, want := range map[string]string{"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "UNKNOWN": "info", "": "info", "weird": "info"} {
		if got := severityFor(in); got != want {
			t.Fatalf("severityFor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPickCVSSFallsBack(t *testing.T) {
	scores := map[string]cvss{
		"zeta": {V2Score: 5, V2Vector: "AV:N"},
		"nvd":  {V40Score: 8.7, V40Vector: "CVSS:4.0/AV:N"},
	}
	if s, v := pickCVSS(scores, "ghsa"); s != 8.7 || v != "CVSS:4.0/AV:N" {
		t.Fatalf("want NVD v4.0 when the severity source has none, got %v %q", s, v)
	}
	if s, _ := pickCVSS(map[string]cvss{"zeta": {V2Score: 5}}, ""); s != 5 {
		t.Fatalf("want any source as last resort, got %v", s)
	}
	if s, v := pickCVSS(nil, "nvd"); s != 0 || v != "" {
		t.Fatalf("want zero for no CVSS, got %v %q", s, v)
	}
}

func TestExecuteUpdatesDBExclusivelyThenScansShared(t *testing.T) {
	a, f := fakeAdapter(t, "", nil)
	if _, err := collect(t, a, context.Background(), validInputs); err != nil {
		t.Fatal(err)
	}
	tmp := "TMPDIR=" + filepath.Join(f.cache, "tmp")
	want := []string{"download:--download-db-only " + tmp, "scan"}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls = %q, want %q (no Java DB without Java archives)", f.calls, want)
	}
	if !slices.Equal(f.locks, []string{"exclusive", "shared"}) {
		t.Fatalf("locks = %q", f.locks)
	}
	if _, err := os.Stat(filepath.Join(f.cache, "tmp")); !os.IsNotExist(err) {
		t.Fatalf("download dir must be removed after the update: %v", err)
	}
}

func TestExecuteDownloadsJavaDBOnlyForJavaArchives(t *testing.T) {
	a, f := fakeAdapter(t, "", nil)
	if err := os.MkdirAll(filepath.Join(f.checkout, "lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.checkout, "lib", "app.JAR"), []byte("PK"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := collect(t, a, context.Background(), validInputs); err != nil {
		t.Fatal(err)
	}
	if len(f.calls) != 3 || !strings.HasPrefix(f.calls[1], "download:--download-java-db-only") {
		t.Fatalf("calls = %q, want vuln DB, Java DB, scan", f.calls)
	}
}

func TestHasJavaArchivesIgnoresGitDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "x.jar"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if hasJavaArchives(dir) {
		t.Fatal("archives under .git are not scanned and need no Java DB")
	}
}

func TestExecuteFirstDownloadFailureIsAnError(t *testing.T) {
	a, f := fakeAdapter(t, "", nil)
	f.downloadErr = errors.New("exit status 1")
	_, err := collect(t, a, context.Background(), validInputs)
	if err == nil || !strings.Contains(err.Error(), "mirror unreachable") {
		t.Fatalf("want the download error, got %v", err)
	}
	if slices.Contains(f.calls, "scan") {
		t.Fatal("must not scan without a vulnerability DB")
	}
}

func TestExecuteScansWithCachedDBWhenUpdateFails(t *testing.T) {
	a, f := fakeAdapter(t, "", nil)
	writeMetadata(t, f.cache, vulnDB)
	f.downloadErr = errors.New("exit status 1")
	if _, err := collect(t, a, context.Background(), validInputs); err != nil {
		t.Fatalf("a cached DB must keep the scan going, got %v", err)
	}
	if f.calls[len(f.calls)-1] != "scan" {
		t.Fatalf("calls = %q", f.calls)
	}
}

func TestExecuteSkipsUpdateWhenCacheBusy(t *testing.T) {
	a, f := fakeAdapter(t, "", nil)
	writeMetadata(t, f.cache, vulnDB)
	f.lockErr = errLockTimeout
	if _, err := collect(t, a, context.Background(), validInputs); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.calls, []string{"scan"}) {
		t.Fatalf("calls = %q, want the scan only", f.calls)
	}
}

func TestUpdateWaitsForTheLockWithoutACachedDB(t *testing.T) {
	_, f := fakeAdapter(t, "", nil)
	var waits []time.Duration
	lock := func(_ context.Context, _ string, _ bool, wait time.Duration) (func(), error) {
		waits = append(waits, wait)
		return func() {}, nil
	}
	run := func(context.Context, []string, []string) (string, error) { return "", nil }

	if err := updateDBs(context.Background(), f.cache, f.checkout, false, run, lock); err != nil {
		t.Fatal(err)
	}
	writeMetadata(t, f.cache, vulnDB)
	if err := updateDBs(context.Background(), f.cache, f.checkout, false, run, lock); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(waits, []time.Duration{0, updateLockWait}) {
		t.Fatalf("waits = %v: block until a first DB exists, then bound the wait", waits)
	}
}
