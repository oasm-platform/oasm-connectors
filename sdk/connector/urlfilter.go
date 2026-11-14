package connector

import (
	"fmt"
	"regexp"
	"strings"
)

// Bounds on the user-supplied URL patterns of one job. Go's regexp is RE2
// (linear time, no backtracking), so these cap memory and argv size, not
// ReDoS.
const (
	MaxURLPatterns   = 20
	MaxURLPatternLen = 512
)

// URLFilter decides which discovered URLs a url_discovery job reports, from
// the matchRegex / filterRegex config keys every url_discovery connector
// shares. A URL is kept when it matches ANY match pattern (or there are none)
// and NO filter pattern — the same semantics as katana's -mr / -fr, so a
// connector that pushes the patterns down to its tool and one that filters its
// output give identical results.
//
// A nil *URLFilter is valid and allows every URL.
type URLFilter struct {
	match  []*regexp.Regexp
	filter []*regexp.Regexp
}

// NewURLFilter compiles the match and filter patterns (RE2 syntax). Errors name
// the offending config key and index, e.g. "matchRegex[1]: ...", so they can be
// surfaced to the user verbatim.
func NewURLFilter(match, filter []string) (*URLFilter, error) {
	m, err := compileURLPatterns("matchRegex", match)
	if err != nil {
		return nil, err
	}
	f, err := compileURLPatterns("filterRegex", filter)
	if err != nil {
		return nil, err
	}
	return &URLFilter{match: m, filter: f}, nil
}

// Active reports whether any pattern is configured.
func (f *URLFilter) Active() bool {
	return f != nil && (len(f.match) > 0 || len(f.filter) > 0)
}

// Allow reports whether u should be reported.
func (f *URLFilter) Allow(u string) bool {
	if f == nil {
		return true
	}
	for _, re := range f.filter {
		if re.MatchString(u) {
			return false
		}
	}
	if len(f.match) == 0 {
		return true
	}
	for _, re := range f.match {
		if re.MatchString(u) {
			return true
		}
	}
	return false
}

func compileURLPatterns(key string, patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) > MaxURLPatterns {
		return nil, fmt.Errorf("%s: at most %d patterns, got %d", key, MaxURLPatterns, len(patterns))
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for i, p := range patterns {
		if strings.TrimSpace(p) == "" {
			return nil, fmt.Errorf("%s[%d]: empty pattern", key, i)
		}
		if len(p) > MaxURLPatternLen {
			return nil, fmt.Errorf("%s[%d]: longer than %d characters", key, i, MaxURLPatternLen)
		}
		// A URL never contains a raw line break, and connectors that hand the
		// patterns to their tool write them one per line.
		if strings.ContainsAny(p, "\r\n") {
			return nil, fmt.Errorf("%s[%d]: must not contain line breaks", key, i)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: invalid RE2 regex: %w", key, i, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}
