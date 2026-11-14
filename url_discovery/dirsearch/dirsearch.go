package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	httphelper "github.com/oasm-platform/oasm-connectors/sdk/http"
)

// dirsearchConfig mirrors manifest.yaml configSchema. Keys are camelCase to
// match the OASM_CONFIG JSON shape the Worker ships per job.
type dirsearchConfig struct {
	Wordlist          string   `json:"wordlist"` // enum; default -> dicc.txt
	Extensions        []string `json:"extensions"`
	Threads           int      `json:"threads"` // dirsearch -t, default 25 when 0
	Recursive         bool     `json:"recursive"`
	MaxRecursionDepth int      `json:"maxRecursionDepth"`
	IncludeStatus     string   `json:"includeStatus"`
	ExcludeStatus     string   `json:"excludeStatus"`
	ExcludeExtensions []string `json:"excludeExtensions"`
	Method            string   `json:"method"`
	Headers           []string `json:"headers"`
	Proxy             string   `json:"proxy"`
	Timeout           int      `json:"timeout"` // dirsearch --timeout seconds
	RandomUserAgent   bool     `json:"randomUserAgent"`
	MaxTime           int      `json:"maxTime"`     // dirsearch --max-time seconds
	MatchRegex        []string `json:"matchRegex"`  // adapter-side URL filter (--exclude-regex matches the body, not the URL)
	FilterRegex       []string `json:"filterRegex"` // adapter-side URL filter
	MaxUrls           int      `json:"maxUrls"`     // adapter-level cap, default 10000 when <=0
}

// loadDirsearchConfig reads the per-job config profile: the job's own config on
// ctx first (a warm-pool container keeps its first run's OASM_CONFIG env), then
// OASM_CONFIG. An unset or empty value yields a zero config (defaults applied
// in buildDirsearchArgs), not an error; malformed JSON is an error.
func loadDirsearchConfig(ctx context.Context) (*dirsearchConfig, error) {
	return connector.LoadConfig[dirsearchConfig](ctx)
}

// resolveDirsearchWordlist maps the config wordlist enum to an absolute path
// under DIRSEARCH_WORDLIST_DIR (default /opt/wordlists/dirsearch). "default"
// (and empty) select dicc.txt; every other enum value selects <name>.txt.
func resolveDirsearchWordlist(cfg *dirsearchConfig) string {
	dir := os.Getenv("DIRSEARCH_WORDLIST_DIR")
	if dir == "" {
		dir = "/opt/wordlists/dirsearch"
	}
	name := cfg.Wordlist
	if name == "" || name == "default" {
		return filepath.Join(dir, "dicc.txt")
	}
	return filepath.Join(dir, name+".txt")
}

// buildDirsearchArgs assembles the dirsearch CLI arg vector in a fixed order.
// -w and -t are always emitted (wordlist resolved explicitly, default threads
// applied) for deterministic argv; optional flags are omitted when zero.
//
// Deliberately NOT exposed: path-valued flags (--config, --log, --raw,
// --sessions-dir, --nmap-report, --proxies-file, --headers-file), DB flags
// (--mysql-url, --postgres-url, -O sqlite), multi-target inputs (-l/--stdin/
// --cidr), and --exit-on-error (its default False is what the unreachable-
// target exit-0 policy relies on).
func buildDirsearchArgs(baseURL, wordlistPath, outFile string, cfg *dirsearchConfig) []string {
	threads := cfg.Threads
	if threads == 0 {
		threads = 25
	}

	args := []string{
		"-u", baseURL,
		"-O", "json",
		"-o", outFile,
		"-q",
		"--no-color",
		"-w", wordlistPath,
	}
	if len(cfg.Extensions) > 0 {
		args = append(args, "-e", strings.Join(cfg.Extensions, ","))
	}
	args = append(args, "-t", strconv.Itoa(threads))
	if cfg.Recursive {
		args = append(args, "-r")
		if cfg.MaxRecursionDepth > 0 {
			args = append(args, "-R", strconv.Itoa(cfg.MaxRecursionDepth))
		}
	}
	if cfg.IncludeStatus != "" {
		args = append(args, "-i", cfg.IncludeStatus)
	}
	if cfg.ExcludeStatus != "" {
		args = append(args, "-x", cfg.ExcludeStatus)
	}
	if len(cfg.ExcludeExtensions) > 0 {
		args = append(args, "--exclude-extensions", strings.Join(cfg.ExcludeExtensions, ","))
	}
	if cfg.Method != "" {
		args = append(args, "-m", cfg.Method)
	}
	for _, h := range cfg.Headers {
		args = append(args, "-H", h)
	}
	if proxy := httphelper.ProxyOrEnv(cfg.Proxy); proxy != "" {
		args = append(args, "-p", proxy)
	}
	if cfg.Timeout > 0 {
		args = append(args, "--timeout", strconv.Itoa(cfg.Timeout))
	}
	if cfg.RandomUserAgent {
		args = append(args, "--random-agent")
	}
	if cfg.MaxTime > 0 {
		args = append(args, "--max-time", strconv.Itoa(cfg.MaxTime))
	}

	return args
}
