package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/oasm-platform/oasm-connectors/sdk/gitrepo"
)

const sampleReport = `[
  {
    "RuleID": "generic-api-key",
    "Description": "Detected a Generic API Key.",
    "StartLine": 3,
    "EndLine": 3,
    "File": "%DIR%/config/app.env",
    "Commit": "",
    "Secret": "REDACTED",
    "Match": "REDACTED",
    "Tags": ["api"]
  },
  {
    "RuleID": "private-key",
    "Description": "Identified a Private Key.",
    "StartLine": 1,
    "EndLine": 27,
    "File": "deploy/id_rsa",
    "Commit": "feedface",
    "Tags": []
  }
]`

// fakeAdapter wires a checkout dir and a gitleaks run that writes `report`
// to the --report-path it is given, recording the args.
func fakeAdapter(t *testing.T, report string, runErr error) (GitleaksAdapter, *[]string, string) {
	t.Helper()
	dir := t.TempDir()
	var gotArgs []string
	return GitleaksAdapter{
		clone: func(_ context.Context, _ gitrepo.Inputs, opts gitrepo.Options) (*gitrepo.Checkout, error) {
			return &gitrepo.Checkout{Dir: dir, Commit: "c0ffee"}, nil
		},
		run: func(_ context.Context, args []string) (string, error) {
			gotArgs = args
			if runErr != nil {
				return "boom on stderr", runErr
			}
			for i, a := range args {
				if a == "--report-path" {
					content := strings.ReplaceAll(report, "%DIR%", filepath.ToSlash(dir))
					if err := os.WriteFile(args[i+1], []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			return "", nil
		},
	}, &gotArgs, dir
}

func collect(t *testing.T, a GitleaksAdapter, ctx context.Context, inputs map[string]any) ([]connector.Finding, error) {
	t.Helper()
	out := make(chan connector.Finding, 16)
	err := a.Execute(ctx, inputs, out)
	close(out)
	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

var validInputs = map[string]any{"repository": "https://github.com/acme/web", "ref": "main"}

func TestExecuteStreamsRedactedFindings(t *testing.T) {
	a, args, _ := fakeAdapter(t, sampleReport, nil)

	findings, err := collect(t, a, context.Background(), validInputs)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(findings))
	}

	first := findings[0]
	if first.FilePath != "config/app.env" || first.LineStart != 3 || first.Commit != "c0ffee" {
		t.Fatalf("tree finding not mapped: %+v", first)
	}
	if first.Severity != "high" || first.Fingerprint != "generic-api-key:config/app.env:3" {
		t.Fatalf("severity/fingerprint: %+v", first)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("finding must be transportable: %v", err)
	}

	second := findings[1]
	if second.Severity != "critical" || second.Commit != "feedface" || second.LineEnd != 27 {
		t.Fatalf("history finding not mapped: %+v", second)
	}

	joined := strings.Join(*args, " ")
	for _, want := range []string{"dir ", "--redact", "--exit-code 0", "--report-format json"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("args %q missing %q", joined, want)
		}
	}
}

func TestExecuteNeverForwardsSecretValues(t *testing.T) {
	a, _, _ := fakeAdapter(t, sampleReport, nil)
	findings, err := collect(t, a, context.Background(), validInputs)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		blob := strings.Join([]string{f.Name, f.Description, f.Solution, f.MatchedAt}, " ")
		if strings.Contains(blob, "REDACTED") {
			t.Fatalf("report Secret/Match leaked into the finding: %+v", f)
		}
	}
}

func TestExecuteHistoryScan(t *testing.T) {
	a, args, _ := fakeAdapter(t, "[]", nil)
	var gotDepth int
	clone := a.clone
	a.clone = func(ctx context.Context, in gitrepo.Inputs, opts gitrepo.Options) (*gitrepo.Checkout, error) {
		gotDepth = opts.Depth
		return clone(ctx, in, opts)
	}
	ctx := connector.WithConfig(context.Background(), `{"scanHistory":true,"historyDepth":25}`)

	if _, err := collect(t, a, ctx, validInputs); err != nil {
		t.Fatal(err)
	}
	if gotDepth != 25 {
		t.Fatalf("clone depth = %d, want 25", gotDepth)
	}
	joined := strings.Join(*args, " ")
	if !strings.HasPrefix(joined, "git ") || !strings.Contains(joined, "--max-count=25") {
		t.Fatalf("history args wrong: %q", joined)
	}
}

func TestExecuteNoLeaks(t *testing.T) {
	a, _, _ := fakeAdapter(t, "", nil)
	findings, err := collect(t, a, context.Background(), validInputs)
	if err != nil || len(findings) != 0 {
		t.Fatalf("want no findings and no error, got %d / %v", len(findings), err)
	}
}

func TestExecuteToolFailure(t *testing.T) {
	a, _, _ := fakeAdapter(t, "", errors.New("exit status 126"))
	_, err := collect(t, a, context.Background(), validInputs)
	if err == nil || !strings.Contains(err.Error(), "boom on stderr") {
		t.Fatalf("want tool failure with stderr, got %v", err)
	}
}

func TestExecuteRejectsUnsafeInputs(t *testing.T) {
	a, _, _ := fakeAdapter(t, "[]", nil)
	if _, err := collect(t, a, context.Background(), map[string]any{"repository": "file:///etc"}); err == nil {
		t.Fatal("want an error for a file:// repository")
	}
	if err := a.Validate(context.Background(), map[string]any{}); err == nil {
		t.Fatal("Validate must reject missing repository")
	}
}

func TestExecuteStopsOnCancel(t *testing.T) {
	a, _, _ := fakeAdapter(t, sampleReport, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out := make(chan connector.Finding) // unbuffered: nothing ever reads it
	if err := a.Execute(ctx, validInputs, out); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestClampDepth(t *testing.T) {
	for in, want := range map[int]int{0: defaultHistoryDepth, -5: defaultHistoryDepth, 10: 10, 999999: maxHistoryDepth} {
		if got := clampDepth(in); got != want {
			t.Fatalf("clampDepth(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestRelativePath(t *testing.T) {
	root := filepath.Join(t.TempDir(), "repo")
	if got := relativePath(filepath.Join(root, "a", "b.env"), root); got != "a/b.env" {
		t.Fatalf("got %q", got)
	}
	if got := relativePath("already/relative.txt", root); got != "already/relative.txt" {
		t.Fatalf("got %q", got)
	}
}

func TestParseReportRejectsGarbage(t *testing.T) {
	if _, err := parseReport([]byte("not json")); err == nil {
		t.Fatal("want an error for a malformed report")
	}
}
