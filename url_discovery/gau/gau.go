package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// gauConfig mirrors manifest.yaml configSchema. Keys are camelCase to match the
// OASM_CONFIG JSON shape the Worker ships per job.
type gauConfig struct {
	Providers []string `json:"providers"` // wayback|commoncrawl|otx|urlscan
	Subs      bool     `json:"subs"`
	Threads   int      `json:"threads"` // gau --threads, default 5 when 0
	Timeout   int      `json:"timeout"` // gau --timeout seconds, default 45 when 0
	Retries   int      `json:"retries"` // gau --retries, default 5 when 0
	Proxy     string   `json:"proxy"`
	From      string   `json:"from"` // YYYYMM
	To        string   `json:"to"`   // YYYYMM
}

// loadGauConfig reads the per-job config profile from OASM_CONFIG. An unset or
// empty value yields a zero config (defaults applied in buildGauArgs), not an
// error; malformed JSON is an error.
func loadGauConfig() (*gauConfig, error) {
	raw := strings.TrimSpace(os.Getenv("OASM_CONFIG"))
	if raw == "" {
		return &gauConfig{}, nil
	}
	var cfg gauConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}
	return &cfg, nil
}

// buildGauArgs assembles the gau CLI arg vector. Threads/timeout/retries are
// always emitted (defaults applied) for deterministic argv; optional flags are
// omitted when zero.
//
// Deliberately NOT exposed (broken/unusable in gau v2.2.4): --json drops URLs
// without an extension, --blacklist never matches, --fp is broken, and --o
// appends to a file while swallowing stdout. Plain stdout is one URL per line;
// dedupe/filtering is done client-side in the adapter.
func buildGauArgs(target string, cfg *gauConfig) []string {
	threads := cfg.Threads
	if threads == 0 {
		threads = 5
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 45
	}
	retries := cfg.Retries
	if retries == 0 {
		retries = 5
	}

	args := []string{
		"--threads", strconv.Itoa(threads),
		"--timeout", strconv.Itoa(timeout),
		"--retries", strconv.Itoa(retries),
	}
	if len(cfg.Providers) > 0 {
		args = append(args, "--providers", strings.Join(cfg.Providers, ","))
	}
	if cfg.Subs {
		args = append(args, "--subs")
	}
	if cfg.Proxy != "" {
		args = append(args, "--proxy", cfg.Proxy)
	}
	if cfg.From != "" {
		args = append(args, "--from", cfg.From)
	}
	if cfg.To != "" {
		args = append(args, "--to", cfg.To)
	}

	return append(args, target)
}
