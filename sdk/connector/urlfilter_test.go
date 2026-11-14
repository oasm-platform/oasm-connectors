package connector

import (
	"strings"
	"testing"
)

func TestURLFilterWithoutPatternsAllowsEverything(t *testing.T) {
	f, err := NewURLFilter(nil, nil)
	if err != nil {
		t.Fatalf("NewURLFilter: %v", err)
	}
	if f.Active() {
		t.Error("Active() = true, want false without patterns")
	}
	if !f.Allow("https://example.com/anything") {
		t.Error("Allow() = false, want true without patterns")
	}

	var nilFilter *URLFilter
	if nilFilter.Active() || !nilFilter.Allow("https://example.com/") {
		t.Error("a nil *URLFilter must be inactive and allow every URL")
	}
}

func TestURLFilterKeepsURLsMatchingAnyMatchPattern(t *testing.T) {
	f, err := NewURLFilter([]string{`/login`, `/admin(/|$)`}, nil)
	if err != nil {
		t.Fatalf("NewURLFilter: %v", err)
	}
	cases := map[string]bool{
		"https://example.com/login":         true,
		"https://example.com/admin":         true,
		"https://example.com/admin/users":   true,
		"https://example.com/administrator": false,
		"https://example.com/about":         false,
	}
	for u, want := range cases {
		if got := f.Allow(u); got != want {
			t.Errorf("Allow(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestURLFilterDropsURLsMatchingAnyFilterPattern(t *testing.T) {
	f, err := NewURLFilter(nil, []string{`\.(png|css)$`, `/static/`})
	if err != nil {
		t.Fatalf("NewURLFilter: %v", err)
	}
	cases := map[string]bool{
		"https://example.com/logo.png":   false,
		"https://example.com/static/app": false,
		"https://example.com/login":      true,
	}
	for u, want := range cases {
		if got := f.Allow(u); got != want {
			t.Errorf("Allow(%q) = %v, want %v", u, got, want)
		}
	}
}

func TestURLFilterFilterPatternWinsOverMatchPattern(t *testing.T) {
	f, err := NewURLFilter([]string{`/login`}, []string{`/login\?logout`})
	if err != nil {
		t.Fatalf("NewURLFilter: %v", err)
	}
	if !f.Allow("https://example.com/login") {
		t.Error("plain login URL must be kept")
	}
	if f.Allow("https://example.com/login?logout=1") {
		t.Error("a URL matching both lists must be dropped")
	}
}

func TestURLFilterRejectsInvalidPatterns(t *testing.T) {
	tooMany := make([]string, MaxURLPatterns+1)
	for i := range tooMany {
		tooMany[i] = "a"
	}
	cases := []struct {
		name           string
		match, filter  []string
		wantErrContain string
	}{
		{"syntax error names field and index", []string{"ok", "(unclosed"}, nil, "matchRegex[1]"},
		{"lookahead is not RE2", nil, []string{`/(?=admin)`}, "filterRegex[0]"},
		{"empty pattern", []string{""}, nil, "matchRegex[0]: empty pattern"},
		{"blank pattern", nil, []string{"   "}, "filterRegex[0]: empty pattern"},
		{"raw newline", []string{"a\nb"}, nil, "matchRegex[0]: must not contain line breaks"},
		{"too long", []string{strings.Repeat("a", MaxURLPatternLen+1)}, nil, "matchRegex[0]: longer than"},
		{"too many", tooMany, nil, "matchRegex: at most"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewURLFilter(tc.match, tc.filter)
			if err == nil {
				t.Fatal("NewURLFilter: want error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrContain) {
				t.Errorf("error %q does not contain %q", err, tc.wantErrContain)
			}
		})
	}
}
