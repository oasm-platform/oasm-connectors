package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
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
	templates       []string
	filters         nuclei.TemplateFilters
	rateLimit       int
	concurrency     int
	followRedirects bool
	idMode          bool
	noInteractsh    bool
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
	if cfg.RateLimit != nil && *cfg.RateLimit > 0 {
		rl = *cfg.RateLimit
	}
	c := 25
	if cfg.Concurrency != nil && *cfg.Concurrency > 0 {
		c = *cfg.Concurrency
	}
	fr := cfg.FollowRedirects != nil && *cfg.FollowRedirects

	return params{templates, filters, rl, c, fr, idMode, true}
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
	opts = append(opts, nuclei.WithConcurrency(nuclei.Concurrency{
		TemplateConcurrency:           p.concurrency,
		HostConcurrency:               25,
		HeadlessHostConcurrency:       10,
		HeadlessTemplateConcurrency:   10,
		JavascriptTemplateConcurrency: 1,
		TemplatePayloadConcurrency:    25,
		ProbeConcurrency:              50,
	}))
	if p.noInteractsh {
		// NoInteractsh:true alone panics (CacheSize=0 → gcache Build).
		// Backfill the SDK's DefaultOptions cache fields so init() succeeds
		// while the client stays lazy (poll/URL short-circuit on NoInteractsh).
		opts = append(opts, nuclei.WithInteractshOptions(nuclei.InteractshOpts{
			NoInteractsh: true,
			CacheSize:    5000,
			Eviction:     60 * time.Second,
			PollDuration: 5 * time.Second,
		}))
	}
	return opts
}

// Validate is intentionally a no-op: inputs are validated upstream by the
// worker node against the connector's inputsSchema.
func (a *NucleiAdapter) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

// Execute runs nuclei against target using the in-process SDK engine and
// streams findings to out. Engine panics are recovered and returned as errors.
func (a *NucleiAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) (retErr error) {
	defer func() {
		if r := recover(); r != nil {
			retErr = fmt.Errorf("nuclei engine panic: %v", r)
		}
	}()

	target, _ := inputs["target"].(string)
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("target required")
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target
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

	cfg, err := parseConfig(os.Getenv("OASM_CONFIG"))
	if err != nil {
		return fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}

	p := scanParams(cfg, dir)
	nuclei.DefaultConfig.SetTemplatesDir(p.templates[0])

	engine, err := nuclei.NewNucleiEngineCtx(ctx, sdkOptions(ctx, p)...)
	if err != nil {
		return fmt.Errorf("nuclei engine: %w", err)
	}
	defer engine.Close()

	engine.Options().FollowRedirects = p.followRedirects
	engine.LoadTargets([]string{target}, false)

	findings, skipped := 0, 0
	defer func() { log.Printf("nuclei: done findings=%d skipped=%d", findings, skipped) }()

	scanErr := engine.ExecuteCallbackWithCtx(ctx, func(ev *nucleiOutput.ResultEvent) {
		sent, err := emitFinding(ctx, ev, out, resultEventToFinding)
		if err != nil {
			return
		}
		if sent {
			findings++
		} else {
			skipped++
		}
	})

	if scanErr != nil {
		if errors.Is(scanErr, nuclei.ErrNoTemplatesAvailable) {
			return fmt.Errorf("nuclei scan: no templates available")
		}
		if errors.Is(scanErr, nuclei.ErrNoTargetsAvailable) {
			return fmt.Errorf("nuclei scan: no targets available")
		}
		return fmt.Errorf("nuclei scan: %w", scanErr)
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

// emitFinding maps a nuclei result event to a Finding and sends it to the
// output channel. It wraps panic recovery on the engine goroutine.
// mapFn defaults to resultEventToFinding; injectable for testing.
func emitFinding(
	ctx context.Context,
	ev *nucleiOutput.ResultEvent,
	out chan<- connector.Finding,
	mapFn func(*nucleiOutput.ResultEvent) (connector.Finding, error),
) (sent bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			sent = false
			err = fmt.Errorf("nuclei event handler panic: %v", r)
		}
	}()
	f, mapErr := mapFn(ev)
	if mapErr != nil {
		return false, nil
	}
	select {
	case out <- f:
		return true, nil
	case <-ctx.Done():
		return false, ctx.Err()
	}
}
