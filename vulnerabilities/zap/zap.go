package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// zapConfig mirrors manifest.yaml configSchema. Keys are camelCase to match
// the OASM_CONFIG JSON shape the Worker ships per job.
type zapConfig struct {
	ScanMode              string `json:"scanMode"`              // baseline|full, default baseline
	MaxSpiderDepth        int    `json:"maxSpiderDepth"`        // spider maxDepth, default 5
	MaxSpiderDuration     int    `json:"maxSpiderDuration"`     // spider/passiveScan-wait maxDuration minutes, default 5
	MaxScanDurationInMins int    `json:"maxScanDurationInMins"` // activeScan cap minutes, default 10
	DelayInMs             int    `json:"delayInMs"`             // activeScan request delay
	ThreadPerHost         int    `json:"threadPerHost"`         // activeScan threads per host
	Policy                string `json:"policy"`                // activeScan policy, default "Default Policy"
	EnableAjaxSpider      bool   `json:"enableAjaxSpider"`      // needs a browser; default off
}

// loadZapConfig reads the per-job config profile from OASM_CONFIG. An unset or
// empty value yields a zero config (defaults applied in buildAutomationPlan),
// not an error; malformed JSON is an error.
func loadZapConfig() (*zapConfig, error) {
	raw := strings.TrimSpace(os.Getenv("OASM_CONFIG"))
	if raw == "" {
		return &zapConfig{}, nil
	}
	var cfg zapConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}
	return &cfg, nil
}

// normalizeTarget turns a bare host or partial URL into the full URL ZAP
// expects as its context target: "example.com" -> "https://example.com".
func normalizeTarget(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		s = "https://" + s
	}
	return s
}

// --- Automation Framework plan model ---

type zapPlan struct {
	Env  zapEnv   `yaml:"env"`
	Jobs []zapJob `yaml:"jobs"`
}

type zapEnv struct {
	Contexts   []zapContext `yaml:"contexts"`
	Parameters zapEnvParams `yaml:"parameters"`
}

type zapContext struct {
	Name         string   `yaml:"name"`
	URLs         []string `yaml:"urls"`
	IncludePaths []string `yaml:"includePaths"`
	ExcludePaths []string `yaml:"excludePaths"`
}

type zapEnvParams struct {
	FailOnError      bool `yaml:"failOnError"`
	FailOnWarning    bool `yaml:"failOnWarning"`
	ProgressToStdout bool `yaml:"progressToStdout"`
}

type zapJob struct {
	Type       string         `yaml:"type"`
	Parameters map[string]any `yaml:"parameters,omitempty"`
}

// buildAutomationPlan renders the ZAP Automation Framework YAML for one scan.
// The report job is the ONLY output channel — its JSON is parsed into findings
// and never surfaced as a user-facing report. scanMode baseline runs
// spider + passive scan only; full opts into the active scanner.
func buildAutomationPlan(target string, cfg *zapConfig, reportPath string) ([]byte, error) {
	mode := strings.ToLower(strings.TrimSpace(cfg.ScanMode))
	if mode == "" {
		mode = "baseline"
	}
	if mode != "baseline" && mode != "full" {
		return nil, fmt.Errorf("invalid scanMode %q (want baseline|full)", cfg.ScanMode)
	}

	spiderDepth := cfg.MaxSpiderDepth
	if spiderDepth <= 0 {
		spiderDepth = 5
	}
	spiderDuration := cfg.MaxSpiderDuration
	if spiderDuration <= 0 {
		spiderDuration = 5
	}
	activeDuration := cfg.MaxScanDurationInMins
	if activeDuration <= 0 {
		activeDuration = 10
	}
	threads := cfg.ThreadPerHost
	if threads <= 0 {
		threads = 2
	}
	policy := strings.TrimSpace(cfg.Policy)
	if policy == "" {
		policy = "Default Policy"
	}

	plan := zapPlan{
		Env: zapEnv{
			Contexts: []zapContext{{
				Name: "oasm",
				URLs: []string{target},
				// QuoteMeta keeps a target like example.com from becoming a
				// host-unanchored regex (the dots would match any character).
				IncludePaths: []string{regexp.QuoteMeta(target) + ".*"},
				ExcludePaths: []string{},
			}},
			Parameters: zapEnvParams{
				FailOnError:      false,
				FailOnWarning:    false,
				ProgressToStdout: true,
			},
		},
		Jobs: []zapJob{
			{Type: "passiveScan-config", Parameters: map[string]any{"maxAlertsPerRule": 0}},
			{Type: "spider", Parameters: map[string]any{
				"context": "oasm", "url": target,
				"maxDepth": spiderDepth, "maxDuration": spiderDuration,
			}},
		},
	}

	if cfg.EnableAjaxSpider {
		plan.Jobs = append(plan.Jobs, zapJob{Type: "spiderAjax", Parameters: map[string]any{
			"context": "oasm", "url": target,
		}})
	}

	plan.Jobs = append(plan.Jobs, zapJob{Type: "passiveScan-wait", Parameters: map[string]any{
		"maxDuration": spiderDuration,
	}})

	if mode == "full" {
		plan.Jobs = append(plan.Jobs, zapJob{Type: "activeScan", Parameters: map[string]any{
			"context": "oasm", "policy": policy,
			"maxScanDurationInMins": activeDuration,
			"delayInMs":             cfg.DelayInMs,
			"threadPerHost":         threads,
		}})
	}

	plan.Jobs = append(plan.Jobs, zapJob{Type: "report", Parameters: map[string]any{
		"template":   "traditional-json",
		"reportDir":  filepath.Dir(reportPath),
		"reportFile": filepath.Base(reportPath),
	}})

	out, err := yaml.Marshal(plan)
	if err != nil {
		return nil, fmt.Errorf("zap: render plan: %w", err)
	}
	return out, nil
}
