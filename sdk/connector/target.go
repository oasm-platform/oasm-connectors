package connector

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// HostOnly strips scheme/userinfo/path/query/port, leaving the bare host:
// "https://example.com/a/b?x=1" -> "example.com", "[::1]:8080" -> "::1".
// Returns "" for blank input.
func HostOnly(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	// net/url resolves userinfo and IPv6 literals correctly; a bare
	// "host:port" is not a URL, so it falls through to the manual strip.
	if u, err := url.Parse(s); err == nil && u.Host != "" {
		return u.Hostname()
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 {
			return s[1:i]
		}
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	return s
}

// WebURL turns a bare host or partial URL into a full http(s) URL, defaulting
// to https. Port, path and query survive: "example.com:8443" ->
// "https://example.com:8443". Returns "" for blank input.
func WebURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return s
}

// HostOf returns the host[:port] of a URL, or target verbatim when it is not
// one — the fallback Finding.Host when a scanner report omits it.
func HostOf(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Host
	}
	return target
}

// SingleHost extracts exactly one host from inputs["target"] for network
// scanners. A URL or "host:port" is reduced to its host, but scope-expanding
// syntax (CIDR "10.0.0.0/24", ranges, lists, wildcards) is REJECTED rather than
// silently narrowed: one job, one host.
func SingleHost(inputs map[string]any) (string, error) {
	raw, _ := inputs["target"].(string)
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("target required")
	}
	if host := singleHost(trimmed); host != "" {
		return host, nil
	}
	return "", fmt.Errorf("invalid target %q (single host only, no CIDR/range/list)", raw)
}

func singleHost(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		// The CIDR check runs before any strip: "10.0.0.0/24" is scope, not a path.
		if _, err := strconv.Atoi(s[i+1:]); err == nil {
			return ""
		}
		s = s[:i]
	}
	if !validHost(s) && !strings.Contains(s, ":") {
		return ""
	}
	// net.SplitHostPort handles "host:port" and "[v6]:port"; a bare bracketed
	// IPv6 literal has no port and is kept verbatim. A non-numeric port
	// ("example.com:80-90") is port-range syntax — reject it.
	if h, p, err := net.SplitHostPort(s); err == nil {
		if _, err := strconv.Atoi(p); err != nil {
			return ""
		}
		s = h
	}
	if !validHost(s) {
		return ""
	}
	return s
}

// validHost accepts a hostname, IPv4 literal or bracketed IPv6 literal —
// never a range (/ * , - ?) or list.
func validHost(h string) bool {
	if h == "" || len(h) > 255 {
		return false
	}
	if strings.ContainsAny(h, "/*?,; \t\n\r") || strings.Contains(h, "..") {
		return false
	}
	if strings.Contains(h, ":") {
		// IPv6 literal (or its zoned form) — only inside brackets.
		return strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]")
	}
	return true
}

// ResolveIPv4 returns the first IPv4 address of host, host verbatim when it
// already is an IP literal, or "" when it cannot be resolved.
func ResolveIPv4(host string) string {
	h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if net.ParseIP(h) != nil {
		return h
	}
	addrs, err := net.LookupHost(h)
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if net.ParseIP(a) != nil && strings.Contains(a, ".") {
			return a
		}
	}
	return ""
}
