package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// rustscanConfig mirrors manifest.yaml configSchema. Keys are camelCase to match
// the OASM_CONFIG JSON shape the Worker ships per job.
//
// There is no "top" knob on purpose: `--top` claims "use the top 1000 ports" but
// scans the whole 1-65535 range in both 2.3.0 and 2.4.1 (verified: a listener on
// 55555 is still reported with --top). Exposing a flag that silently ignores
// what it documents is worse than not exposing it.
type rustscanConfig struct {
	Ports     string `json:"ports"`     // rustscan -p: comma-separated list, e.g. "80,443"
	Range     string `json:"range"`     // rustscan -r: start-end, e.g. "1-1024"; ignored when Ports is set
	TimeoutMs int    `json:"timeoutMs"` // rustscan -t: ms before a port counts closed, 0 = rustscan default (1500)
	Tries     int    `json:"tries"`     // rustscan --tries: 0 = rustscan default (1)
	BatchSize int    `json:"batchSize"` // rustscan -b: concurrent sockets, 0 = rustscan default (4500)
	UDP       bool   `json:"udp"`       // rustscan --udp
}

// loadRustscanConfig reads the per-job config profile from OASM_CONFIG. An unset
// or empty value yields a zero config (defaults applied in buildRustscanArgs),
// not an error; malformed JSON is an error.
func loadRustscanConfig() (*rustscanConfig, error) {
	raw := strings.TrimSpace(os.Getenv("OASM_CONFIG"))
	if raw == "" {
		return &rustscanConfig{}, nil
	}
	var cfg rustscanConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}
	return &cfg, nil
}

// portInRange keeps every validated port inside the TCP/UDP port space; a value
// outside it is a typo, not a scan of something real.
func portInRange(n int) bool { return n >= 1 && n <= 65535 }

// validPortList accepts rustscan -p grammar only: a comma-separated list of
// digits. Everything else is rejected before it reaches argv, so a malformed or
// hostile spec cannot smuggle a flag into the rustscan command line. Ranges are
// NOT accepted here — rustscan -p rejects "1-1000" (exit 2), that is -r.
func validPortList(s string) bool {
	if s == "" {
		return false
	}
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(part)
		if err != nil || !portInRange(n) {
			return false
		}
	}
	return true
}

// validPortRange accepts rustscan -r grammar: "<start>-<end>", start <= end,
// both inside the port space.
func validPortRange(s string) bool {
	start, end, ok := strings.Cut(s, "-")
	if !ok || strings.Contains(end, "-") {
		return false
	}
	lo, err1 := strconv.Atoi(start)
	hi, err2 := strconv.Atoi(end)
	return err1 == nil && err2 == nil && portInRange(lo) && portInRange(hi) && lo <= hi
}

// validTargetHost accepts a hostname, IPv4 literal or bracketed IPv6 literal —
// a single host, never a range or a list. rustscan -a takes CIDRs, lists and
// files of targets, so its scope-expanding operators (, / *) are rejected here:
// the connector's contract is one target per job.
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
	// A non-numeric "port" ("example.com:80-90") is a port-range, not an
	// address — reject it rather than hand rustscan an ambiguous target.
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

// buildRustscanArgs assembles the rustscan CLI arg vector.
//
// -g (greppable) is MANDATORY: it is the only machine-readable contract this
// adapter parses — "host -> [80,443]" on stdout — and it is also what stops
// rustscan from shelling out to nmap for service detection.
// -n (no-config) is MANDATORY: a config file at $HOME/.rustscan.toml would
// silently override the profile the Worker shipped.
//
// Deliberately NOT exposed: --scripts (nmap scripts), -c (config path),
// --resolver, --ulimit, -x, --scan-order, --top, and -a with more than one host.
func buildRustscanArgs(target string, cfg *rustscanConfig) []string {
	args := []string{"-g", "-n"}
	if cfg.UDP {
		args = append(args, "--udp")
	}
	// rustscan's own default (no port flag at all) is the FULL 1-65535 range,
	// so a zero config means "scan everything" — the manifest says so.
	if cfg.Ports != "" {
		args = append(args, "-p", cfg.Ports)
	} else if cfg.Range != "" {
		args = append(args, "-r", cfg.Range)
	}
	if cfg.BatchSize > 0 {
		args = append(args, "-b", strconv.Itoa(cfg.BatchSize))
	}
	if cfg.TimeoutMs > 0 {
		args = append(args, "-t", strconv.Itoa(cfg.TimeoutMs))
	}
	if cfg.Tries > 0 {
		args = append(args, "--tries", strconv.Itoa(cfg.Tries))
	}
	return append(args, "-a", target)
}
