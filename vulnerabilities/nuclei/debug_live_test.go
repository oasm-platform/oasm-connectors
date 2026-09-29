//go:build debuglive

package main

// Live-scan harness. Opt-in via `go test -tags debuglive -run TestDebugLiveScan`.
//
// It reproduces Execute()'s engine wiring exactly (scanParams + sdkOptions +
// LoadTargets + ExecuteCallbackWithCtx) but exposes the knobs under debug as
// env vars, so a live result set can be diffed against `nuclei -u <target>`:
//
//	DEBUG_TARGET          scan target (default honey.scanme.sh)
//	NUCLEI_TEMPLATE_DIR   templates dir (default /opt/nuclei-templates)
//	OASM_CONFIG           connector config JSON (same payload the worker injects)
//	DEBUG_TAGS            override p.filters.Tags (CSV)
//	DEBUG_SEVERITY        override p.filters.Severity (CSV)
//	DEBUG_TEMPLATE_IDS    override p.filters.IDs (CSV)
//	DEBUG_NO_INTERACTSH   "true"/"false" (default: whatever scanParams sets)
//	DEBUG_TIMEOUT         Go duration (default 20m)
//	DEBUG_OUT             findings JSON output path (default debug-live-findings.json)

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envCSV(key string) []string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func TestDebugLiveScan(t *testing.T) {
	target := envOr("DEBUG_TARGET", "honey.scanme.sh")
	dir := envOr("NUCLEI_TEMPLATE_DIR", defaultTemplateDir)
	outFile := envOr("DEBUG_OUT", "debug-live-findings.json")
	timeout := 20 * time.Minute
	if v := os.Getenv("DEBUG_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("bad DEBUG_TIMEOUT: %v", err)
		}
		timeout = d
	}

	cfg, err := parseConfig(os.Getenv("OASM_CONFIG"))
	if err != nil {
		t.Fatalf("OASM_CONFIG: %v", err)
	}
	p := scanParams(cfg, dir)

	// Knob overrides — applied after scanParams so we compare "what the
	// connector does today" against "the same wiring with one thing changed".
	if v := envCSV("DEBUG_TAGS"); v != nil {
		p.filters.Tags = v
	}
	if v := os.Getenv("DEBUG_SEVERITY"); v != "" {
		p.filters.Severity = v
	}
	if v := envCSV("DEBUG_TEMPLATE_IDS"); v != nil {
		p.filters.IDs = v
	}
	if v := os.Getenv("DEBUG_NO_INTERACTSH"); v != "" {
		p.noInteractsh = v == "true"
	}

	t.Logf("target=%s dir=%s", target, dir)
	t.Logf("filters: severity=%q tags=%v excludeTags=%v ids=%v", p.filters.Severity, p.filters.Tags, p.filters.ExcludeTags, p.filters.IDs)
	t.Logf("rateLimit=%d concurrency=%d followRedirects=%v noInteractsh=%v", p.rateLimit, p.concurrency, p.followRedirects, p.noInteractsh)

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		// mirror Execute(): bare host gets https://
		if !strings.Contains(target, ":") {
			target = "https://" + target
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	nuclei.DefaultConfig.SetTemplatesDir(p.templates[0])

	start := time.Now()
	opts := sdkOptions(ctx, p)
	if os.Getenv("DEBUG_VERBOSE") == "true" {
		// sdkOptions sets Silent:true; WithVerbosity overwrites all verbosity
		// fields, so appending it last re-enables engine logging.
		opts = append(opts, nuclei.WithVerbosity(nuclei.VerbosityOptions{Verbose: true}))
	}
	engine, err := nuclei.NewNucleiEngineCtx(ctx, opts...)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer engine.Close()

	engine.Options().FollowRedirects = p.followRedirects
	engine.LoadTargets([]string{target}, false)

	var findings []connector.Finding
	scanErr := engine.ExecuteCallbackWithCtx(ctx, func(ev *nucleiOutput.ResultEvent) {
		f, mErr := resultEventToFinding(ev)
		if mErr != nil {
			t.Logf("skipped event: %v", mErr)
			return
		}
		findings = append(findings, f)
	})

	elapsed := time.Since(start)
	bySeverity := map[string]int{}
	for _, f := range findings {
		bySeverity[f.Severity]++
	}
	t.Logf("RESULT findings=%d elapsed=%s scanErr=%v", len(findings), elapsed.Round(time.Second), scanErr)
	t.Logf("RESULT bySeverity=%v", bySeverity)
	for _, f := range findings {
		t.Logf("FINDING [%s] %s @ %s", f.Severity, f.Name, f.MatchedAt)
	}

	blob, _ := json.MarshalIndent(map[string]any{
		"target":        target,
		"noInteractsh":  p.noInteractsh,
		"severity":      p.filters.Severity,
		"tags":          p.filters.Tags,
		"elapsedSec":    elapsed.Seconds(),
		"count":         len(findings),
		"bySeverity":    bySeverity,
		"scanErr":       errString(scanErr),
		"findings":      findings,
		"templateDir":   dir,
		"oasmConfigRaw": os.Getenv("OASM_CONFIG"),
	}, "", "  ")
	if err := os.WriteFile(outFile, blob, 0o600); err != nil {
		t.Fatalf("write %s: %v", outFile, err)
	}
	t.Logf("wrote %s", outFile)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// TestDebugTemplateLoad reports how many templates an engine built from this
// checkout can actually load out of NUCLEI_TEMPLATE_DIR, plus the parse errors
// the engine surfaces. This isolates "engine too old for the baked template
// collection" from "template filters selected nothing".
func TestDebugTemplateLoad(t *testing.T) {
	dir := envOr("NUCLEI_TEMPLATE_DIR", defaultTemplateDir)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	nuclei.DefaultConfig.SetTemplatesDir(dir)

	p := scanParams(Config{}, dir)
	if v := envCSV("DEBUG_TAGS"); v != nil {
		p.filters.Tags = v
	}
	if v := os.Getenv("DEBUG_SEVERITY"); v != "" {
		p.filters.Severity = v
	}

	engine, err := nuclei.NewNucleiEngineCtx(ctx, sdkOptions(ctx, p)...)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer engine.Close()

	errs := engine.LoadAllTemplates()
	t.Logf("LOAD dir=%s templates=%d workflows=%d loadErr=%v", dir, len(engine.GetTemplates()), len(engine.GetWorkflows()), errs)
}
