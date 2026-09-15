package main

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// katanaConfig mirrors manifest.yaml configSchema. Keys are camelCase to match
// the OASM_CONFIG JSON shape the Worker ships per job.
//
// JsCrawl is a pointer so "unset" is distinguishable from an explicit false:
// nil defaults to true (parse JavaScript endpoints; no browser needed), while
// an explicit false omits -jc entirely.
type katanaConfig struct {
	Depth                  int      `json:"depth"`                  // katana -d, default 3 when 0
	JsCrawl                *bool    `json:"jsCrawl"`                // katana -jc, default true when nil
	CrawlDuration          int      `json:"crawlDuration"`          // katana -ct seconds, 0 = unbounded
	Timeout                int      `json:"timeout"`                // katana -timeout seconds, default 10 when 0
	Concurrency            int      `json:"concurrency"`            // katana -c, default 10 when 0
	Parallelism            int      `json:"parallelism"`            // katana -p, default 10 when 0
	RateLimit              int      `json:"rateLimit"`              // katana -rl, default 150 when 0
	Retries                int      `json:"retries"`                // katana -retry, default 1 when 0
	Proxy                  string   `json:"proxy"`                  // katana -proxy
	Headers                []string `json:"headers"`                // katana -H (repeatable)
	FilterSimilar          bool     `json:"filterSimilar"`          // katana -fsu
	FilterSimilarThreshold int      `json:"filterSimilarThreshold"` // katana -fst, default 10 when 0
	MaxDomainPages         int      `json:"maxDomainPages"`         // katana -mdp, omitted when 0
	ExtensionMatch         []string `json:"extensionMatch"`         // katana -em
	ExtensionFilter        []string `json:"extensionFilter"`        // katana -ef
	CrawlScope             string   `json:"crawlScope"`             // katana -cs
	MaxUrls                int      `json:"maxUrls"`                // adapter-level cap, default 10000 when 0
}

// katanaRunnerInitMarker is the stderr substring katana prints when the runner
// fails to initialize. It is the ONLY signal for that failure: katana exits 0
// in that case (measured), so the exit code cannot be trusted.
const katanaRunnerInitMarker = "could not create runner"

// loadKatanaConfig reads the per-job config profile from OASM_CONFIG. An unset
// or empty value yields a zero config (defaults applied in buildKatanaArgs),
// not an error; malformed JSON is an error.
func loadKatanaConfig() (*katanaConfig, error) {
	raw := strings.TrimSpace(os.Getenv("OASM_CONFIG"))
	if raw == "" {
		return &katanaConfig{}, nil
	}
	var cfg katanaConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}
	return &cfg, nil
}

// jsCrawlEnabled reports whether -jc should be emitted: nil (key absent)
// defaults to true; an explicit false disables it.
func jsCrawlEnabled(cfg *katanaConfig) bool {
	return cfg.JsCrawl == nil || *cfg.JsCrawl
}

// csvQuoteHeader quotes a header line when its value contains a comma or a
// double quote. katana declares -H as pflag `string[]`, which splits each raw
// argument on commas using encoding/csv semantics; without quoting, a value
// like "Accept: text/html,application/json" would be split into two bogus
// headers. Quoting makes encoding/csv parse it back as a single value.
func csvQuoteHeader(h string) string {
	if !strings.ContainsAny(h, `,"`) {
		return h
	}
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	// ponytail: Write can only fail on the underlying io.Writer; bytes.Buffer never errors.
	_ = w.Write([]string{h})
	w.Flush()
	return strings.TrimRight(buf.String(), "\r\n")
}

// buildKatanaArgs assembles the katana CLI arg vector. Core flags are always
// emitted (defaults applied) for a deterministic argv; conditionals follow a
// fixed order and the target is last.
//
// -duc (disable update check) is MANDATORY and always first: without it katana
// performs a startup egress GET to https://api.pdtm.sh/api/v1/tools/katana.
//
// Deliberately NOT exposed:
//   - headless browser flags (-hl/-hh/-sc/-sb/-nos/-cdd/-xhr/-aff/-csp/-csk):
//     need chromium (~hundreds of MB); documented upgrade path only.
//   - scope-escape flags (-ns/-do/-cos): a job must never crawl outside the
//     target's registered domain.
//   - -jsl/-jsluice: memory-intensive experimental JS analysis; -jc covers it.
//   - output flags (-o/-ot/-sr/-or/-ob/-j/-jsonl/-sf/-field): they break the
//     URL-only stdout contract the worker's findingToDiscoveredUrl depends on
//     (and file output swallows stdout).
//   - form/field extraction (-fx/-fc/-flc): not URL discovery; katana writes
//     its own defaults under $HOME/.config/katana/.
//   - match/filter regex/dsl and tuning flags (-mr/-fr/-mdc/-fdc/-iqp/-pc/-dr/
//     -s/-kf/-r/-e/-td/-tlsi/-rd/-rlm/-hrl/-mrs/-time-stable/-duf/-ndef/-up/
//     -resume/-health-check/-config/-v/-debug/-elog/-pprof-server): outside the
//     URL-discovery contract; deterministic argv stays minimal.
//
// -fs is never emitted: katana's default -fs rdn (registered domain) is exactly
// the scope we want.
func buildKatanaArgs(target string, cfg *katanaConfig) []string {
	depth := cfg.Depth
	if depth == 0 {
		depth = 3
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 10
	}
	concurrency := cfg.Concurrency
	if concurrency == 0 {
		concurrency = 10
	}
	parallelism := cfg.Parallelism
	if parallelism == 0 {
		parallelism = 10
	}
	rateLimit := cfg.RateLimit
	if rateLimit == 0 {
		rateLimit = 150
	}
	retries := cfg.Retries
	if retries == 0 {
		retries = 1
	}

	args := []string{
		"-duc",
		"-silent",
		"-nc",
		"-d", strconv.Itoa(depth),
		"-ct", strconv.Itoa(cfg.CrawlDuration),
		"-timeout", strconv.Itoa(timeout),
		"-c", strconv.Itoa(concurrency),
		"-p", strconv.Itoa(parallelism),
		"-rl", strconv.Itoa(rateLimit),
		"-retry", strconv.Itoa(retries),
	}
	if jsCrawlEnabled(cfg) {
		args = append(args, "-jc")
	}
	if cfg.FilterSimilar {
		threshold := cfg.FilterSimilarThreshold
		if threshold == 0 {
			threshold = 10
		}
		args = append(args, "-fsu", "-fst", strconv.Itoa(threshold))
	}
	if cfg.MaxDomainPages > 0 {
		args = append(args, "-mdp", strconv.Itoa(cfg.MaxDomainPages))
	}
	if cfg.CrawlScope != "" {
		args = append(args, "-cs", cfg.CrawlScope)
	}
	if len(cfg.ExtensionMatch) > 0 {
		args = append(args, "-em", strings.Join(cfg.ExtensionMatch, ","))
	}
	if len(cfg.ExtensionFilter) > 0 {
		args = append(args, "-ef", strings.Join(cfg.ExtensionFilter, ","))
	}
	if cfg.Proxy != "" {
		args = append(args, "-proxy", cfg.Proxy)
	}
	for _, h := range cfg.Headers {
		args = append(args, "-H", csvQuoteHeader(h))
	}

	return append(args, "-u", target)
}
