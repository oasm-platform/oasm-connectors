package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// nmapConfig mirrors manifest.yaml configSchema. Keys are camelCase to match
// the OASM_CONFIG JSON shape the Worker ships per job.
//
// Ports deliberately has no default here: an empty Ports with TopPorts == 0
// means "let nmap scan its own default top-1000 set" — the adapter emits no
// -p flag at all rather than hardcoding a list that drifts from nmap.
type nmapConfig struct {
	Ports       string `json:"ports"`       // nmap -p (e.g. "22,80,443" or "1-1024")
	TopPorts    int    `json:"topPorts"`    // nmap --top-ports N; ignored when Ports is set
	HostTimeout int    `json:"hostTimeout"` // nmap --host-timeout seconds, 0 = nmap default (no limit)
	Retries     int    `json:"retries"`     // nmap --max-retries N
	NoPing      *bool  `json:"noPing"`      // nmap -Pn; nil defaults to true
}

// loadNmapConfig reads the per-job config profile from OASM_CONFIG. An unset or
// empty value yields a zero config (defaults applied in buildNmapArgs), not an
// error; malformed JSON is an error.
func loadNmapConfig() (*nmapConfig, error) {
	raw := strings.TrimSpace(os.Getenv("OASM_CONFIG"))
	if raw == "" {
		return &nmapConfig{}, nil
	}
	var cfg nmapConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}
	return &cfg, nil
}

// noPingEnabled reports whether -Pn should be emitted: nil (key absent)
// defaults to true.
func noPingEnabled(cfg *nmapConfig) bool { return cfg.NoPing == nil || *cfg.NoPing }

// validPortSpec accepts only what nmap's -p grammar allows: digits, commas and
// hyphens. Everything else is rejected before it reaches argv, so a malformed
// or hostile spec cannot smuggle a flag into the nmap command line.
func validPortSpec(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != ',' && r != '-' {
			return false
		}
	}
	return true
}

// validTargetHost accepts a hostname, IPv4 literal or bracketed IPv6 literal —
// a single host, never a range or a list. nmap's CIDR/range/wildcard grammar
// (/ * , - ?) is rejected so one job cannot fan a scan out across a whole
// network: the connector's contract is one target, and the scope-expanding
// operators are left to a deliberate, separate feature.
func validTargetHost(h string) bool {
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

// normalizeTarget strips scheme/userinfo/port from a target so an operator can
// paste a URL or "host:port". A path or query is discarded, and a target whose
// "path" is actually numeric scope syntax ("10.0.0.0/24") is REJECTED rather
// than silently narrowed to one host — the CIDR check runs before any strip.
// Returns "" for input that is not a single host.
func normalizeTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.LastIndex(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		if _, err := strconv.Atoi(s[i+1:]); err == nil {
			return ""
		}
		s = s[:i]
	}
	if !validTargetHost(s) && !strings.Contains(s, ":") {
		return ""
	}
	// net.SplitHostPort handles both "host:port" and "[v6]:port"; a bare
	// bracketed IPv6 literal has no port to split and is kept verbatim. A
	// non-numeric "port" ("example.com:80-90") is nmap port-range syntax, not
	// an address — reject it rather than hand nmap an ambiguous target.
	if h, p, err := net.SplitHostPort(s); err == nil {
		if _, err := strconv.Atoi(p); err != nil {
			return ""
		}
		s = h
	}
	if !validTargetHost(s) {
		return ""
	}
	return s
}

// buildNmapArgs assembles the nmap CLI arg vector.
//
// -oX - (XML on stdout) is MANDATORY: it is the only machine-readable contract
// the adapter parses. -oG/-oN are never used so stderr stays diagnostics-only.
// No scan-type flag is emitted: an unprivileged container can only do a TCP
// connect scan, and nmap already falls back to it, so asking for -sT would just
// be a lie about the raw-socket scans (-sS/-sU/-O, NSE) this connector does not
// support without CAP_NET_RAW.
//
// Deliberately NOT exposed: -sS/-sU/-O/-A/--script and -iL/-iR (raw sockets,
// root-only, or scan fan-out outside the one-target contract).
func buildNmapArgs(target string, cfg *nmapConfig) []string {
	args := []string{"-Pn", "-n", "-oX", "-"}
	if cfg.Ports != "" {
		// A bare port list means "just these ports": without -p nmap would
		// keep service/version probing on its own 1000-port default.
		args = append(args, "-p", cfg.Ports)
	} else if cfg.TopPorts > 0 {
		args = append(args, "--top-ports", strconv.Itoa(cfg.TopPorts))
	}
	if cfg.HostTimeout > 0 {
		args = append(args, "--host-timeout", fmt.Sprintf("%ds", cfg.HostTimeout))
	}
	if cfg.Retries > 0 {
		args = append(args, "--max-retries", strconv.Itoa(cfg.Retries))
	}
	return append(args, target)
}
