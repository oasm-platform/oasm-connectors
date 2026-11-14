package main

import (
	"context"
	"strconv"
	"strings"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// arjunConfig mirrors manifest.yaml configSchema. Keys are camelCase to match
// the OASM_CONFIG JSON shape the Worker ships per job.
type arjunConfig struct {
	Wordlist         string   `json:"wordlist"`         // small|medium|large, passed verbatim as Arjun's own -w shortcut
	Method           string   `json:"method"`           // GET|POST|XML|JSON, default GET
	Threads          int      `json:"threads"`          // -t, default 5
	ChunkSize        int      `json:"chunkSize"`        // -c, default 250 (upstream forces 500 when method != GET)
	Timeout          int      `json:"timeout"`          // -T seconds, default 15
	Delay            float64  `json:"delay"`            // -d seconds, only emitted when > 0
	Stable           bool     `json:"stable"`           // --stable
	RateLimit        int      `json:"rateLimit"`        // --rate-limit, default 9999
	DisableRedirects bool     `json:"disableRedirects"` // --disable-redirects
	Headers          []string `json:"headers"`          // --headers, joined with \n; omitted when empty
	Include          string   `json:"include"`          // --include, only when set
	MatchRegex       []string `json:"matchRegex"`       // adapter-side filter on "<url>?<param>=" (Arjun has no URL regex flag)
	FilterRegex      []string `json:"filterRegex"`      // adapter-side filter on "<url>?<param>="
	MaxUrls          int      `json:"maxUrls"`          // adapter-level cap, default 10000 when <= 0
}

// loadArjunConfig reads the per-job config profile: the job's own config on ctx
// first (a warm-pool container keeps its first run's OASM_CONFIG env), then
// OASM_CONFIG. An unset or empty value yields a zero config (defaults applied
// in buildArjunArgs), not an error; malformed JSON is an error.
func loadArjunConfig(ctx context.Context) (*arjunConfig, error) {
	return connector.LoadConfig[arjunConfig](ctx)
}

// buildArjunArgs assembles the Arjun CLI arg vector in a fixed, deterministic
// order. -w/-m/-t/-c/-T/--rate-limit are always emitted (defaults applied);
// optional flags are omitted when unset.
//
// Deliberately NOT exposed: -oB (proxy replay), --passive (contacts
// web.archive.org/otx/commoncrawl), -oT (text output), -i (import), --casing.
// --headers is never emitted bare: an empty list would launch Arjun's nano.
func buildArjunArgs(baseURL, outFile string, cfg *arjunConfig) []string {
	wordlist := cfg.Wordlist
	if wordlist == "" {
		wordlist = "medium"
	}
	method := cfg.Method
	if method == "" {
		method = "GET"
	}
	threads := cfg.Threads
	if threads == 0 {
		threads = 5
	}
	chunkSize := cfg.ChunkSize
	if chunkSize == 0 {
		chunkSize = 250
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 15
	}
	rateLimit := cfg.RateLimit
	if rateLimit == 0 {
		rateLimit = 9999
	}

	args := []string{
		"-u", baseURL,
		"-oJ", outFile,
		"-w", wordlist,
		"-m", method,
		"-t", strconv.Itoa(threads),
		"-c", strconv.Itoa(chunkSize),
		"-T", strconv.Itoa(timeout),
	}
	if cfg.Delay > 0 {
		args = append(args, "-d", strconv.FormatFloat(cfg.Delay, 'f', -1, 64))
	}
	if cfg.Stable {
		args = append(args, "--stable")
	}
	args = append(args, "--rate-limit", strconv.Itoa(rateLimit))
	if len(cfg.Headers) > 0 {
		args = append(args, "--headers", strings.Join(cfg.Headers, "\n"))
	}
	if cfg.Include != "" {
		args = append(args, "--include", cfg.Include)
	}
	if cfg.DisableRedirects {
		args = append(args, "--disable-redirects")
	}

	return args
}
