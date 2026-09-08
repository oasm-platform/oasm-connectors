package main

import "testing"

// ---------------------------------------------------------------------------
// scanParams — table-driven tests for config → SDK params mapping
// ---------------------------------------------------------------------------

func TestScanParams(t *testing.T) {
	tests := []struct {
		name  string
		cfg   Config
		dir   string
		check func(t *testing.T, p params)
	}{
		{
			name: "empty config yields defaults",
			cfg:  Config{},
			dir:  defaultTemplateDir,
			check: func(t *testing.T, p params) {
				assertSliceEqual(t, "templates", p.templates, []string{defaultTemplateDir})
				if p.filters.Severity != "" {
					t.Errorf("filters.Severity = %q, want empty", p.filters.Severity)
				}
				if p.filters.Tags != nil {
					t.Errorf("filters.Tags = %v, want nil", p.filters.Tags)
				}
				if p.filters.ExcludeTags != nil {
					t.Errorf("filters.ExcludeTags = %v, want nil", p.filters.ExcludeTags)
				}
				if p.filters.IDs != nil {
					t.Errorf("filters.IDs = %v, want nil", p.filters.IDs)
				}
				if p.rateLimit != 150 {
					t.Errorf("rateLimit = %d, want 150", p.rateLimit)
				}
				if p.concurrency != 25 {
					t.Errorf("concurrency = %d, want 25", p.concurrency)
				}
				if p.followRedirects {
					t.Errorf("followRedirects = true, want false")
				}
				if p.idMode {
					t.Errorf("idMode = true, want false")
				}
			},
		},
		{
			name: "severity single",
			cfg:  Config{Severity: []string{"high"}},
			dir:  defaultTemplateDir,
			check: func(t *testing.T, p params) {
				if p.filters.Severity != "high" {
					t.Errorf("filters.Severity = %q, want %q", p.filters.Severity, "high")
				}
			},
		},
		{
			name: "severity multiple csv",
			cfg:  Config{Severity: []string{"high", "critical"}},
			dir:  defaultTemplateDir,
			check: func(t *testing.T, p params) {
				if p.filters.Severity != "high,critical" {
					t.Errorf("filters.Severity = %q, want %q", p.filters.Severity, "high,critical")
				}
			},
		},
		{
			name: "tags",
			cfg:  Config{Tags: []string{"cve", "xss"}},
			dir:  defaultTemplateDir,
			check: func(t *testing.T, p params) {
				assertSliceEqual(t, "filters.Tags", p.filters.Tags, []string{"cve", "xss"})
			},
		},
		{
			name: "excludeTags",
			cfg:  Config{ExcludeTags: []string{"dos"}},
			dir:  defaultTemplateDir,
			check: func(t *testing.T, p params) {
				assertSliceEqual(t, "filters.ExcludeTags", p.filters.ExcludeTags, []string{"dos"})
			},
		},
		{
			name: "templateIds with severity+tags (id-mode priority)",
			cfg: Config{
				Severity:    []string{"high"},
				Tags:        []string{"cve"},
				TemplateIds: []string{"CVE-2021-1234"},
			},
			dir: defaultTemplateDir,
			check: func(t *testing.T, p params) {
				if !p.idMode {
					t.Error("idMode = false, want true")
				}
				assertSliceEqual(t, "filters.IDs", p.filters.IDs, []string{"CVE-2021-1234"})
				if p.filters.Severity != "" {
					t.Errorf("filters.Severity = %q, want empty (id mode drops severity)", p.filters.Severity)
				}
				if p.filters.Tags != nil {
					t.Errorf("filters.Tags = %v, want nil (id mode drops tags)", p.filters.Tags)
				}
				if p.filters.ExcludeTags != nil {
					t.Errorf("filters.ExcludeTags = %v, want nil (id mode drops excludeTags)", p.filters.ExcludeTags)
				}
			},
		},
		{
			name: "rateLimit",
			cfg:  Config{RateLimit: intPtr(100)},
			dir:  defaultTemplateDir,
			check: func(t *testing.T, p params) {
				if p.rateLimit != 100 {
					t.Errorf("rateLimit = %d, want 100", p.rateLimit)
				}
			},
		},
		{
			name: "concurrency",
			cfg:  Config{Concurrency: intPtr(50)},
			dir:  defaultTemplateDir,
			check: func(t *testing.T, p params) {
				if p.concurrency != 50 {
					t.Errorf("concurrency = %d, want 50", p.concurrency)
				}
			},
		},
		{
			name: "followRedirects true",
			cfg:  Config{FollowRedirects: boolPtr(true)},
			dir:  defaultTemplateDir,
			check: func(t *testing.T, p params) {
				if !p.followRedirects {
					t.Error("followRedirects = false, want true")
				}
			},
		},
		{
			name: "followRedirects false",
			cfg:  Config{FollowRedirects: boolPtr(false)},
			dir:  defaultTemplateDir,
			check: func(t *testing.T, p params) {
				if p.followRedirects {
					t.Error("followRedirects = true, want false")
				}
			},
		},
		{
			name: "all fields with templateIds",
			cfg: Config{
				Severity:        []string{"high"},
				Tags:            []string{"cve"},
				TemplateIds:     []string{"CVE-2021-1"},
				RateLimit:       intPtr(200),
				Concurrency:     intPtr(40),
				FollowRedirects: boolPtr(true),
			},
			dir: defaultTemplateDir,
			check: func(t *testing.T, p params) {
				if !p.idMode {
					t.Error("idMode = false, want true")
				}
				assertSliceEqual(t, "filters.IDs", p.filters.IDs, []string{"CVE-2021-1"})
				if p.filters.Severity != "" {
					t.Errorf("filters.Severity = %q, want empty (id mode)", p.filters.Severity)
				}
				if p.filters.Tags != nil {
					t.Errorf("filters.Tags = %v, want nil (id mode)", p.filters.Tags)
				}
				if p.filters.ExcludeTags != nil {
					t.Errorf("filters.ExcludeTags = %v, want nil (id mode)", p.filters.ExcludeTags)
				}
				if p.rateLimit != 200 {
					t.Errorf("rateLimit = %d, want 200", p.rateLimit)
				}
				if p.concurrency != 40 {
					t.Errorf("concurrency = %d, want 40", p.concurrency)
				}
				if !p.followRedirects {
					t.Error("followRedirects = false, want true")
				}
			},
		},
		{
			name: "templates dir override",
			cfg:  Config{},
			dir:  "/custom/dir",
			check: func(t *testing.T, p params) {
				assertSliceEqual(t, "templates", p.templates, []string{"/custom/dir"})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := scanParams(tc.cfg, tc.dir)
			tc.check(t, p)
		})
	}
}

// assertSliceEqual compares two string slices element-by-element.
func assertSliceEqual(t *testing.T, label string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: len = %d, want %d (%v vs %v)", label, len(got), len(want), got, want)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %q, want %q", label, i, got[i], want[i])
		}
	}
}
