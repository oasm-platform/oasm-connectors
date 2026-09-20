package main

import (
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const testReportPath = "/tmp/work/report.json"

func TestLoadZapConfig_EmptyIsNoop(t *testing.T) {
	t.Setenv("OASM_CONFIG", "")
	cfg, err := loadZapConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil zero config")
	}
}

func TestLoadZapConfig_InvalidErrors(t *testing.T) {
	t.Setenv("OASM_CONFIG", "{bad json")
	if _, err := loadZapConfig(); err == nil {
		t.Fatal("expected error for invalid OASM_CONFIG")
	}
}

func TestNormalizeTarget(t *testing.T) {
	cases := map[string]string{
		"":                       "",
		"  ":                     "",
		"example.com":            "https://example.com",
		"https://example.com":    "https://example.com",
		"http://a.example/x?y=1": "http://a.example/x?y=1",
	}
	for in, want := range cases {
		if got := normalizeTarget(in); got != want {
			t.Errorf("normalizeTarget(%q) = %q, want %q", in, got, want)
		}
	}
}

func parsePlan(t *testing.T, target string, cfg *zapConfig) zapPlan {
	t.Helper()
	raw, err := buildAutomationPlan(target, cfg, testReportPath)
	if err != nil {
		t.Fatalf("buildAutomationPlan: %v", err)
	}
	var plan zapPlan
	if err := yaml.Unmarshal(raw, &plan); err != nil {
		t.Fatalf("plan is not valid YAML: %v\n%s", err, raw)
	}
	return plan
}

func jobByType(plan zapPlan, typ string) (zapJob, bool) {
	for _, j := range plan.Jobs {
		if j.Type == typ {
			return j, true
		}
	}
	return zapJob{}, false
}

func TestBuildAutomationPlan_Baseline(t *testing.T) {
	plan := parsePlan(t, "https://example.com", &zapConfig{})

	for _, typ := range []string{"passiveScan-config", "spider", "passiveScan-wait", "report"} {
		if _, ok := jobByType(plan, typ); !ok {
			t.Errorf("baseline plan missing %q job", typ)
		}
	}
	if _, ok := jobByType(plan, "activeScan"); ok {
		t.Error("baseline plan must NOT contain an activeScan job")
	}
	if _, ok := jobByType(plan, "spiderAjax"); ok {
		t.Error("ajax spider should be off by default")
	}

	report, _ := jobByType(plan, "report")
	if report.Parameters["template"] != "traditional-json" {
		t.Errorf("report template = %v", report.Parameters["template"])
	}
	if report.Parameters["reportDir"] != filepath.Dir(testReportPath) || report.Parameters["reportFile"] != filepath.Base(testReportPath) {
		t.Errorf("report destination = %v / %v", report.Parameters["reportDir"], report.Parameters["reportFile"])
	}

	spider, _ := jobByType(plan, "spider")
	if spider.Parameters["maxDepth"] != 5 {
		t.Errorf("default maxDepth = %v, want 5", spider.Parameters["maxDepth"])
	}
}

func TestBuildAutomationPlan_FullAddsActiveScan(t *testing.T) {
	plan := parsePlan(t, "https://example.com", &zapConfig{
		ScanMode:              "full",
		Policy:                "Default Policy",
		MaxScanDurationInMins: 20,
		ThreadPerHost:         3,
		DelayInMs:             100,
	})

	active, ok := jobByType(plan, "activeScan")
	if !ok {
		t.Fatal("full plan must contain an activeScan job")
	}
	if active.Parameters["maxScanDurationInMins"] != 20 {
		t.Errorf("active duration = %v", active.Parameters["maxScanDurationInMins"])
	}
	if active.Parameters["threadPerHost"] != 3 {
		t.Errorf("threadPerHost = %v", active.Parameters["threadPerHost"])
	}
	if active.Parameters["delayInMs"] != 100 {
		t.Errorf("delayInMs = %v", active.Parameters["delayInMs"])
	}
}

func TestBuildAutomationPlan_AjaxSpiderOptIn(t *testing.T) {
	plan := parsePlan(t, "https://example.com", &zapConfig{EnableAjaxSpider: true})
	ajax, ok := jobByType(plan, "spiderAjax")
	if !ok {
		t.Fatal("enableAjaxSpider=true should add a spiderAjax job")
	}
	if ajax.Parameters["maxDuration"] != 5 {
		t.Errorf("ajax maxDuration = %v, want 5 (default spider duration)", ajax.Parameters["maxDuration"])
	}
}

// The hard timeout must track the configured budgets, otherwise a scan with a
// long budget is killed before ZAP writes its report.
func TestZapHardTimeout_TracksBudgets(t *testing.T) {
	cases := []struct {
		name string
		cfg  *zapConfig
		want time.Duration
	}{
		{"defaults baseline", &zapConfig{}, 15 * time.Minute},
		{"defaults full", &zapConfig{ScanMode: "full"}, 25 * time.Minute},
		{"long spider", &zapConfig{ScanMode: "full", MaxSpiderDuration: 25}, 65 * time.Minute},
		{"long active", &zapConfig{ScanMode: "full", MaxScanDurationInMins: 60}, 75 * time.Minute},
		{"ajax", &zapConfig{EnableAjaxSpider: true}, 20 * time.Minute},
	}
	for _, c := range cases {
		if got := zapHardTimeout(c.cfg); got != c.want {
			t.Errorf("%s: zapHardTimeout = %s, want %s", c.name, got, c.want)
		}
	}
}

func TestBuildAutomationPlan_InvalidScanMode(t *testing.T) {
	if _, err := buildAutomationPlan("https://example.com", &zapConfig{ScanMode: "turbo"}, "/tmp/r.json"); err == nil {
		t.Fatal("expected error for invalid scanMode")
	}
}

func TestBuildAutomationPlan_EscapesTargetInIncludePaths(t *testing.T) {
	target := "https://example.com"
	plan := parsePlan(t, target, &zapConfig{})
	if len(plan.Env.Contexts) != 1 {
		t.Fatalf("expected 1 context, got %d", len(plan.Env.Contexts))
	}
	want := regexp.QuoteMeta(target) + ".*"
	if plan.Env.Contexts[0].IncludePaths[0] != want {
		t.Errorf("includePaths[0] = %q, want %q", plan.Env.Contexts[0].IncludePaths[0], want)
	}
}
