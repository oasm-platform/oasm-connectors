package main

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	httphelper "github.com/oasm-platform/oasm-connectors/sdk/http"
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
	MatchRegex             []string `json:"matchRegex"`             // katana -mr (pattern file) + adapter filter
	FilterRegex            []string `json:"filterRegex"`            // katana -fr (pattern file) + adapter filter
	MaxUrls                int      `json:"maxUrls"`                // adapter-level cap, default 10000 when 0
}

// katanaPatternFiles holds the paths of the -mr / -fr pattern files; an empty
// path omits the flag.
type katanaPatternFiles struct {
	match  string
	filter string
}

// katanaCanEvaluate reports whether katana evaluates every pattern exactly as
// written. katana declares -mr/-fr with goflags.FileStringSliceOptions, which
// trims each entry and cuts it at the first '#' as a comment (goflags v0.2.1,
// read on both the CLI and the file path), so "#/admin" would silently become
// an empty pattern. Such a list is kept adapter-side only: pushing down part of
// a match list would make katana drop URLs only the omitted patterns match.
func katanaCanEvaluate(patterns []string) bool {
	if len(patterns) == 0 {
		return false
	}
	for _, p := range patterns {
		if strings.Contains(p, "#") || strings.TrimSpace(p) != p {
			return false
		}
	}
	return true
}

// katanaRunnerInitMarker is the stderr substring katana prints when the runner
// fails to initialize. It is the ONLY signal for that failure: katana exits 0
// in that case (measured), so the exit code cannot be trusted.
const katanaRunnerInitMarker = "could not create runner"

// jsCrawlEnabled reports whether -jc should be emitted: nil (key absent)
// defaults to true; an explicit false disables it.
func jsCrawlEnabled(cfg *katanaConfig) bool {
	return cfg.JsCrawl == nil || *cfg.JsCrawl
}

// writeKatanaPatternFiles writes the pattern lists katana can evaluate verbatim
// to one-pattern-per-line files in a fresh temp dir. cleanup removes them and is
// always safe to call, also on error.
func writeKatanaPatternFiles(cfg *katanaConfig) (files katanaPatternFiles, cleanup func(), err error) {
	cleanup = func() {}
	pushMatch, pushFilter := katanaCanEvaluate(cfg.MatchRegex), katanaCanEvaluate(cfg.FilterRegex)
	if !pushMatch && !pushFilter {
		return files, cleanup, nil
	}
	dir, err := os.MkdirTemp("", "katana-patterns-*")
	if err != nil {
		return files, cleanup, fmt.Errorf("katana: pattern dir: %w", err)
	}
	cleanup = func() { _ = os.RemoveAll(dir) }
	write := func(name string, patterns []string) (string, error) {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(strings.Join(patterns, "\n")), 0o600); err != nil {
			return "", fmt.Errorf("katana: write %s: %w", name, err)
		}
		return path, nil
	}
	if pushMatch {
		if files.match, err = write("match.txt", cfg.MatchRegex); err != nil {
			return files, cleanup, err
		}
	}
	if pushFilter {
		if files.filter, err = write("filter.txt", cfg.FilterRegex); err != nil {
			return files, cleanup, err
		}
	}
	return files, cleanup, nil
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
//   - match/filter dsl and tuning flags (-mdc/-fdc/-iqp/-pc/-dr/
//     -s/-kf/-r/-e/-td/-tlsi/-rd/-rlm/-hrl/-mrs/-time-stable/-duf/-ndef/-up/
//     -resume/-health-check/-config/-v/-debug/-elog/-pprof-server): outside the
//     URL-discovery contract; deterministic argv stays minimal.
//
// -fs is never emitted: katana's default -fs rdn (registered domain) is exactly
// the scope we want.
//
// -mr/-fr always point at adapter-written pattern files, never at the raw
// patterns: goflags reads a CLI value that names an existing file as that
// file's lines, so a pattern such as "/etc/hosts" would load a local file.
func buildKatanaArgs(target string, cfg *katanaConfig, files katanaPatternFiles) []string {
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
	if files.match != "" {
		args = append(args, "-mr", files.match)
	}
	if files.filter != "" {
		args = append(args, "-fr", files.filter)
	}
	if proxy := httphelper.ProxyOrEnv(cfg.Proxy); proxy != "" {
		args = append(args, "-proxy", proxy)
	}
	for _, h := range cfg.Headers {
		args = append(args, "-H", csvQuoteHeader(h))
	}

	return append(args, "-u", target)
}
