package main

import (
	"fmt"
	"strconv"
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
