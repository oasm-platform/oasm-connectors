// ==== T1 nuclei SDK API spike (v3.4.1) — consumed by T3/T4/T5 ====
// VERIFIED per-symbol facts from `go doc` against github.com/projectdiscovery/nuclei/v3 v3.4.1:
//
//   - lib.NucleiEngine options (all exist as NucleiSDKOptions funcs):
//     WithTemplatesOrWorkflows(TemplateSources), WithTemplateFilters(TemplateFilters),
//     WithConcurrency(Concurrency), WithVerbosity(VerbosityOptions), DisableUpdateCheck(),
//     WithGlobalRateLimit(maxTokens, duration), WithGlobalRateLimitCtx(ctx, maxTokens, duration),
//     WithInteractshOptions(InteractshOpts), plus WithProxy, WithSandboxOptions, WithScanStrategy,
//     WithHeaders, WithNetworkConfig, EnablePassiveMode, DASTMode, etc.
//   - Global rate limit: BOTH exist; WithGlobalRateLimit is marked Deprecated
//     ("will be removed in favour of WithGlobalRateLimitCtx in next release").
//   - WithInteractshOptions: EXISTS (so T5's interactsh branch is reachable from the lib API).
//   - severity.Holder{Severity Severity `mapping:"true"`}: field Severity is the severity.Severity
//     type, which has `func (severity Severity) String() string` (no pointer receiver).
//   - output.ResultEvent: Info field is `model.Info` (json "info,inline"); no Classification field
//     directly on ResultEvent — classification lives on model.Info.
//   - model.Info fields incl.: Name, Authors, Tags, Description, Impact, Reference (RawStringSlice),
//     SeverityHolder severity.Holder, Metadata, Classification *Classification, Remediation.
//   - installer.TemplateManager: has `func (t *TemplateManager) FreshInstallIfNotExists() error`
//     (and UpdateIfOutdated()).
//   - pkg/types.Options defaults (from DefaultOptions() in pkg/types/types.go, v3.4.1):
//     BulkSize = 25, TemplateThreads = 25.
//
// deps.go (blank imports of lib, pkg/output, pkg/installer, pkg/catalog/config) keeps the v3.4.1
// require from being pruned by `go mod tidy`; deleted in T4 when adapter.go imports lib for real.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// NucleiAdapter implements Validate/Execute for nuclei as a thin wrapper:
// receive input -> exec nuclei -> stream JSONL findings back through the SDK channel.
// Input validation is the worker node layer's responsibility, upstream of here.
type NucleiAdapter struct{}

// Config holds nuclei scan configuration parsed from the OASM_CONFIG env var.
// Fields map to nuclei CLI flags; pointers distinguish "absent" from zero-value.
type Config struct {
	Severity        []string `json:"severity"`
	Tags            []string `json:"tags"`
	ExcludeTags     []string `json:"excludeTags"`
	TemplateIds     []string `json:"templateIds"`
	RateLimit       *int     `json:"rateLimit"`
	Concurrency     *int     `json:"concurrency"`
	FollowRedirects *bool    `json:"followRedirects"`
}

// parseConfig unmarshals a JSON string into Config. An empty or malformed
// string returns a zero Config (no error for empty; error for malformed).
func parseConfig(raw string) (Config, error) {
	if strings.TrimSpace(raw) == "" {
		return Config{}, nil
	}
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// defaultTemplateDir is where the Dockerfile bakes the template collection
// (-ud /opt/nuclei-templates at build time). nuclei itself ignores the
// NUCLEI_TEMPLATES_DIR env var — it honors only -t/-ud flags and its config
// file — so the adapter must pass -t explicitly. Override per-scan via the
// NUCLEI_TEMPLATE_DIR env var for custom layouts.
const defaultTemplateDir = "/opt/nuclei-templates"

// templateDir returns the templates directory: NUCLEI_TEMPLATE_DIR if set,
// else NUCLEI_TEMPLATES_DIR (plural, injected by the worker runtime), else
// the baked-in defaultTemplateDir.
func templateDir() string {
	if d := os.Getenv("NUCLEI_TEMPLATE_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("NUCLEI_TEMPLATES_DIR"); d != "" {
		return d
	}
	return defaultTemplateDir
}

// buildArgs maps a Config to nuclei CLI flags, always ending with -target and -jsonl.
// When TemplateIds is set, only -id is emitted as a filter: -severity/-tags/-etags
// are dropped (with a warning) because mixing -id with template selection filters
// made nuclei silently match nothing and report zero findings. When no config is
// provided the manifest.yaml defaults apply: rateLimit=150, concurrency=25.
func buildArgs(target string, cfg Config) []string {
	var args []string

	// Stable flags first: -duc disables the update check (the container has no
	// network at runtime), -silent hides banner noise, -nc disables colored output.
	args = append(args, "-duc", "-silent", "-nc")

	// Always pin the templates directory: at runtime HOME is a tmpfs, so nuclei's
	// default lookup (HOME/nuclei-templates) finds nothing and aborts with
	// "FTL no templates provided". /opt/nuclei-templates is baked at build time.
	args = append(args, "-t", templateDir())

	if len(cfg.TemplateIds) > 0 {
		if len(cfg.Severity) > 0 || len(cfg.Tags) > 0 || len(cfg.ExcludeTags) > 0 {
			log.Printf("nuclei: templateIds set — dropping -severity/-tags/-etags (incompatible with -id)")
		}
		args = append(args, "-id", strings.Join(cfg.TemplateIds, ","))
	} else {
		if len(cfg.Severity) > 0 {
			args = append(args, "-severity", strings.Join(cfg.Severity, ","))
		}
		if len(cfg.Tags) > 0 {
			args = append(args, "-tags", strings.Join(cfg.Tags, ","))
		}
		if len(cfg.ExcludeTags) > 0 {
			args = append(args, "-etags", strings.Join(cfg.ExcludeTags, ","))
		}
	}

	// Manifest defaults apply when the config leaves them unset (manifest.yaml:
	// rateLimit default 150, concurrency default 25).
	rl := 150
	if cfg.RateLimit != nil {
		rl = *cfg.RateLimit
	}
	args = append(args, "-rl", strconv.Itoa(rl))

	c := 25
	if cfg.Concurrency != nil {
		c = *cfg.Concurrency
	}
	args = append(args, "-c", strconv.Itoa(c))

	if cfg.FollowRedirects != nil && *cfg.FollowRedirects {
		args = append(args, "-follow-redirects")
	}

	args = append(args, "-target", target, "-jsonl")
	return args
}

// redactedArgs returns a copy of args with the value following -target
// replaced by [redacted] so scan targets are not leaked into logs.
func redactedArgs(args []string) []string {
	redacted := make([]string, len(args))
	copy(redacted, args)
	for i, a := range redacted {
		if a == "-target" && i+1 < len(redacted) {
			redacted[i+1] = "[redacted]"
		}
	}
	return redacted
}

// Validate is intentionally a no-op: inputs are validated upstream by the
// worker node against the connector's inputsSchema.
func (a *NucleiAdapter) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

// Execute runs nuclei against target and streams every JSONL finding to out.
// Non-JSON stdout lines (banner/noise) are skipped. A malformed OASM_CONFIG
// fails the execution instead of silently falling back to defaults.
func (a *NucleiAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	target, _ := inputs["target"].(string)
	if target == "" {
		return fmt.Errorf("target required")
	}

	dir := templateDir()
	st, statErr := os.Stat(dir)
	if statErr != nil || !st.IsDir() {
		return fmt.Errorf("nuclei templates dir missing: %s: %v (rebuild image so /opt/nuclei-templates is baked, or set NUCLEI_TEMPLATE_DIR)", dir, statErr)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil || len(entries) == 0 {
		return fmt.Errorf("nuclei templates dir empty: %s (bake failed or volume shadowed it; rm the oasm-nuclei-templates volume)", dir)
	}
	log.Printf("nuclei: using templates dir=%s entries=%d", dir, len(entries))

	// Read optional OASM_CONFIG env — empty → zero Config (manifest defaults
	// apply); malformed → fail loudly instead of silently scanning with defaults.
	cfg, err := parseConfig(os.Getenv("OASM_CONFIG"))
	if err != nil {
		return fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}

	bin := os.Getenv("NUCLEI_BIN")
	if bin == "" {
		bin = "nuclei"
	}
	args := buildArgs(target, cfg)
	log.Printf("nuclei: bin=%s args=%v", bin, redactedArgs(args))
	cmd := exec.CommandContext(ctx, bin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	var stderrTail []byte
	cmd.Stderr = &limitedWriter{buf: &stderrTail, limit: 32 * 1024}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", bin, err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // nuclei JSON lines can be large
	findings, skipped := 0, 0
	done := func() {
		log.Printf("nuclei: done findings=%d skipped=%d", findings, skipped)
	}
	defer done()
	for scanner.Scan() {
		line := scanner.Bytes()
		f, err := parseFinding(line)
		if err != nil {
			skipped++ // banner/noise or unusable lines
			continue
		}
		out <- f
		findings++
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("read stdout: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		// Keep the Done.Error string compatible (contains `exit status N`) while
		// adding the numeric exit code for downstream consumers.
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return fmt.Errorf("nuclei exited: %w (exit code %d); stderr tail: %s", err, code, string(stderrTail))
	}
	return nil
}

// nucleiLine is the subset of a nuclei -jsonl output line the adapter maps
// onto a Finding. `any` fields are used because nuclei emits some values
// either as numbers or as strings depending on version/type.
type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name      string `json:"name"`
		Severity  string `json:"severity"`
		Reference any    `json:"reference"`
		Tags      any    `json:"tags"`
		Solution  string `json:"solution"`
	} `json:"info"`
	Tags        any    `json:"tags"`
	MatchedAt   string `json:"matched-at"`
	Host        string `json:"host"`
	IP          string `json:"ip"`
	CVSSScore   any    `json:"cvss-score"`
	CVSSMetrics string `json:"cvss-metrics"`
	EPSSScore   any    `json:"epss-score"`
	CVEID       any    `json:"cve-id"`
	CWEID       any    `json:"cwe-id"`
	Timestamp   string `json:"timestamp"`
}

// parseFinding maps one nuclei JSONL line onto a connector.Finding. Lines the
// adapter cannot use (noise, malformed JSON, no name at all) yield an error so
// the caller skips them instead of failing the stream. Severity "unknown"
// normalizes to "info" — mirrors nessus mapSeverity's default — so real
// matches never drop; a missing info.name falls back to the template-id.
func parseFinding(line []byte) (connector.Finding, error) {
	var n nucleiLine
	if err := json.Unmarshal(line, &n); err != nil {
		return connector.Finding{}, err
	}

	f := connector.Finding{
		Name:        n.Info.Name,
		Severity:    normalizeSeverity(n.Info.Severity),
		Tags:        toStrings(n.Tags),
		References:  toStrings(n.Info.Reference),
		CVEID:       toStrings(n.CVEID),
		CWEID:       toStrings(n.CWEID),
		CVSSMetrics: n.CVSSMetrics,
		Solution:    n.Info.Solution,
		MatchedAt:   n.MatchedAt,
		Host:        n.Host,
		IP:          n.IP,
	}
	if f.Name == "" {
		f.Name = n.TemplateID
	}
	if score, ok := toFloat64(n.CVSSScore); ok {
		f.CVSSScore = score
	}
	if score, ok := toFloat64(n.EPSSScore); ok {
		f.EPSSScore = score
	}
	if ts, err := time.Parse(time.RFC3339, n.Timestamp); err == nil {
		f.Timestamp = ts
	}
	if f.Name == "" {
		return connector.Finding{}, fmt.Errorf("finding line has no name")
	}
	return f, nil
}

// normalizeSeverity maps a scanner severity onto the Finding enum; anything
// outside it (e.g. nuclei "unknown") becomes "info" rather than killing the
// whole stream at runtime validation.
func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, v := range connector.Severities {
		if s == v {
			return s
		}
	}
	return "info"
}

// toStrings normalizes a JSON value into a string slice, accepting a string
// (comma- or single-valued), an array, or nil.
func toStrings(v any) []string {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
		return out
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		parts := strings.Split(t, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	default:
		return nil
	}
}

// toFloat64 normalizes a JSON number-or-string into a float64.
func toFloat64(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(t), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// limitedWriter keeps only the last `limit` bytes written to it.
type limitedWriter struct {
	buf   *[]byte
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	if len(*w.buf) > w.limit {
		*w.buf = (*w.buf)[len(*w.buf)-w.limit:]
	}
	return len(p), nil
}
