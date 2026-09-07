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
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
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

type params struct {
	templates      []string
	filters        nuclei.TemplateFilters
	rateLimit      int
	concurrency    int
	followRedirects bool
	idMode         bool
}

// scanParams maps a Config + templates directory into a params struct.
// When TemplateIds is set, only filters.IDs is populated: severity/tags/excludeTags
// are dropped because mixing -id with template selection filters made nuclei
// silently match nothing. When no config is provided the manifest.yaml defaults
// apply: rateLimit=150, concurrency=25.
func scanParams(cfg Config, dir string) params {
	templates := []string{dir}
	var filters nuclei.TemplateFilters
	idMode := len(cfg.TemplateIds) > 0
	if idMode {
		filters.IDs = cfg.TemplateIds
		if len(cfg.Severity) > 0 || len(cfg.Tags) > 0 || len(cfg.ExcludeTags) > 0 {
			log.Printf("nuclei: templateIds set — dropping -severity/-tags/-etags (incompatible with -id)")
		}
	} else {
		if len(cfg.Severity) > 0 {
			filters.Severity = strings.Join(cfg.Severity, ",")
		}
		if len(cfg.Tags) > 0 {
			filters.Tags = cfg.Tags
		}
		if len(cfg.ExcludeTags) > 0 {
			filters.ExcludeTags = cfg.ExcludeTags
		}
	}

	rl := 150
	if cfg.RateLimit != nil {
		rl = *cfg.RateLimit
	}
	c := 25
	if cfg.Concurrency != nil {
		c = *cfg.Concurrency
	}
	fr := cfg.FollowRedirects != nil && *cfg.FollowRedirects

	return params{templates, filters, rl, c, fr, idMode}
}

// sdkOptions converts resolved params into nuclei SDK option functions.
// HostConcurrency is hardcoded to 25, matching BulkSize default from
// pkg/types/types.go DefaultOptions() (T1 spike confirmed).
func sdkOptions(ctx context.Context, p params) []nuclei.NucleiSDKOptions {
	opts := []nuclei.NucleiSDKOptions{
		nuclei.DisableUpdateCheck(),
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: p.templates}),
		nuclei.WithVerbosity(nuclei.VerbosityOptions{Silent: true}),
	}
	if p.filters.Severity != "" || p.filters.Tags != nil || p.filters.ExcludeTags != nil || p.filters.IDs != nil {
		opts = append(opts, nuclei.WithTemplateFilters(p.filters))
	}
	opts = append(opts, nuclei.WithGlobalRateLimitCtx(ctx, p.rateLimit, time.Second))
	opts = append(opts, nuclei.WithConcurrency(nuclei.Concurrency{TemplateConcurrency: p.concurrency, HostConcurrency: 25}))
	return opts
}

// buildCLIArgs constructs nuclei CLI flags from resolved params.
// Transitional: used by the exec-based Execute until T4 rewrites it to use
// the nuclei SDK engine directly via sdkOptions.
func buildCLIArgs(target string, p params) []string {
	var args []string
	args = append(args, "-duc", "-silent", "-nc")
	args = append(args, "-t", p.templates[0])
	if p.idMode {
		args = append(args, "-id", strings.Join(p.filters.IDs, ","))
	} else {
		if p.filters.Severity != "" {
			args = append(args, "-severity", p.filters.Severity)
		}
		if p.filters.Tags != nil {
			args = append(args, "-tags", strings.Join(p.filters.Tags, ","))
		}
		if p.filters.ExcludeTags != nil {
			args = append(args, "-etags", strings.Join(p.filters.ExcludeTags, ","))
		}
	}
	args = append(args, "-rl", fmt.Sprintf("%d", p.rateLimit))
	args = append(args, "-c", fmt.Sprintf("%d", p.concurrency))
	if p.followRedirects {
		args = append(args, "-follow-redirects")
	}
	args = append(args, "-target", target, "-jsonl")
	return args
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
	p := scanParams(cfg, dir)
	log.Printf("nuclei: bin=%s templates=%v", bin, p.templates)
	args := buildCLIArgs(target, p)
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
		// Parse straight into the typed event (no hand-rolled JSONL structs);
		// T4 replaces this exec loop with the in-process engine callback.
		var ev nucleiOutput.ResultEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			skipped++ // banner/noise lines are not JSON
			continue
		}
		f, err := resultEventToFinding(&ev)
		if err != nil {
			skipped++ // event without a usable name
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

// resultEventToFinding maps one nuclei SDK output.ResultEvent onto a
// connector.Finding. Events whose name is empty in both info.name and
// template-id yield an error so the caller skips them instead of failing the
// stream. Severity "unknown" normalizes to "info" via normalizeSeverity,
// mirroring the old JSONL parser's no-drop behaviour. StringSlice fields use
// ToSlice() because stringslice models a single string OR a []string.
func resultEventToFinding(event *nucleiOutput.ResultEvent) (connector.Finding, error) {
	name := event.Info.Name
	if name == "" {
		name = event.TemplateID
	}
	if name == "" {
		return connector.Finding{}, fmt.Errorf("finding event has no name")
	}

	f := connector.Finding{
		Name:      name,
		Severity:  normalizeSeverity(event.Info.SeverityHolder.Severity.String()),
		Tags:      event.Info.Tags.ToSlice(),
		Solution:  event.Info.Remediation,
		MatchedAt: event.Matched,
		Host:      event.Host,
		IP:        event.IP,
		Timestamp: event.Timestamp,
	}
	if event.Info.Reference != nil {
		f.References = event.Info.Reference.ToSlice()
	}
	if c := event.Info.Classification; c != nil {
		f.CVEID = c.CVEID.ToSlice()
		f.CWEID = c.CWEID.ToSlice()
		f.CVSSScore = c.CVSSScore
		f.CVSSMetrics = c.CVSSMetrics
		f.EPSSScore = c.EPSSScore
	}
	return f, nil
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
