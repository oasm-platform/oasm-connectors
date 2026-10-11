package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ffufConfig mirrors manifest.yaml configSchema. Keys are camelCase to match the
// OASM_CONFIG JSON shape the Worker ships per job.
type ffufConfig struct {
	Wordlist        string   `json:"wordlist"` // enum, default "common"
	Extensions      []string `json:"extensions"`
	MatchCodes      string   `json:"matchCodes"`
	FilterCodes     string   `json:"filterCodes"`
	FilterSize      string   `json:"filterSize"`
	Recursion       bool     `json:"recursion"`
	RecursionDepth  int      `json:"recursionDepth"` // -recursion-depth, only when >0
	Threads         int      `json:"threads"`        // -t, default 40 when 0
	Rate            int      `json:"rate"`           // -rate, only when >0
	Delay           string   `json:"delay"`          // -p
	Timeout         int      `json:"timeout"`        // -timeout, default 10 when 0
	FollowRedirects bool     `json:"followRedirects"`
	AutoCalibration bool     `json:"autoCalibration"`
	Headers         []string `json:"headers"` // -H once per entry
	Proxy           string   `json:"proxy"`
	Method          string   `json:"method"`
	Data            string   `json:"data"`
	MaxTime         int      `json:"maxTime"` // -maxtime, only when >0
	MaxUrls         int      `json:"maxUrls"` // adapter-level cap, default 10000 when <=0
}

// ffufWordlistFiles maps the configSchema enum to the wordlist file name.
var ffufWordlistFiles = map[string]string{
	"common":                  "common.txt",
	"raft-small-directories":  "raft-small-directories.txt",
	"raft-medium-directories": "raft-medium-directories.txt",
	"big":                     "big.txt",
	"dirbuster-small":         "DirBuster-2007_directory-list-2.3-small.txt",
	"dirbuster-medium":        "DirBuster-2007_directory-list-2.3-medium.txt",
}

// resolveFfufWordlist maps the wordlist enum to an absolute path under
// FFUF_WORDLIST_DIR (default /opt/wordlists/ffuf). An unknown or empty enum
// falls back to "common".
func resolveFfufWordlist(cfg *ffufConfig) string {
	dir := strings.TrimSpace(os.Getenv("FFUF_WORDLIST_DIR"))
	if dir == "" {
		dir = "/opt/wordlists/ffuf"
	}
	file, ok := ffufWordlistFiles[cfg.Wordlist]
	if !ok {
		file = ffufWordlistFiles["common"]
	}
	return filepath.Join(dir, file)
}

// loadFfufConfig reads the per-job config profile from OASM_CONFIG. An unset or
// empty value yields a zero config (defaults applied in buildFfufArgs), not an
// error; malformed JSON is an error.
func loadFfufConfig() (*ffufConfig, error) {
	raw := strings.TrimSpace(os.Getenv("OASM_CONFIG"))
	if raw == "" {
		return &ffufConfig{}, nil
	}
	var cfg ffufConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}
	return &cfg, nil
}

// buildFfufArgs assembles the ffuf CLI arg vector in a fixed deterministic
// order. Threads/timeout are always emitted (defaults applied); optional flags
// are omitted when zero/empty.
//
// Deliberately NOT exposed: file/path-valued flags (-o/-of/-od/-debug-log/
// -config/-request/-D) swallow stdout or read local files; multi-target input
// (-input-cmd, repeated -w) breaks the single-target contract.
//
// -H is emitted once per header with no csv-quoting: ffuf -H is a
// map split on the first colon, not a pflag string[].
func buildFfufArgs(baseURL, wordlistPath string, cfg *ffufConfig) []string {
	threads := cfg.Threads
	if threads == 0 {
		threads = 40
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10
	}

	args := []string{
		"-json",
		"-s",
		"-noninteractive",
		"-u", baseURL + "/FUZZ",
		"-w", wordlistPath,
	}
	if cfg.Method != "" {
		args = append(args, "-X", cfg.Method)
	}
	if cfg.Data != "" {
		args = append(args, "-d", cfg.Data)
	}
	if len(cfg.Extensions) > 0 {
		args = append(args, "-e", strings.Join(cfg.Extensions, ","))
	}
	if cfg.MatchCodes != "" {
		args = append(args, "-mc", cfg.MatchCodes)
	}
	if cfg.FilterCodes != "" {
		args = append(args, "-fc", cfg.FilterCodes)
	}
	if cfg.FilterSize != "" {
		args = append(args, "-fs", cfg.FilterSize)
	}
	args = append(args,
		"-t", strconv.Itoa(threads),
		"-timeout", strconv.Itoa(timeout),
	)
	if cfg.Rate > 0 {
		args = append(args, "-rate", strconv.Itoa(cfg.Rate))
	}
	if cfg.Delay != "" {
		args = append(args, "-p", cfg.Delay)
	}
	if cfg.FollowRedirects {
		args = append(args, "-r")
	}
	if cfg.AutoCalibration {
		args = append(args, "-ac")
	}
	if cfg.Recursion {
		args = append(args, "-recursion")
		if cfg.RecursionDepth > 0 {
			args = append(args, "-recursion-depth", strconv.Itoa(cfg.RecursionDepth))
		}
	}
	if cfg.MaxTime > 0 {
		args = append(args, "-maxtime", strconv.Itoa(cfg.MaxTime))
	}
	for _, h := range cfg.Headers {
		args = append(args, "-H", h)
	}
	if cfg.Proxy != "" {
		args = append(args, "-x", cfg.Proxy)
	}

	return args
}
