package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// NucleiAdapter implements Validate/Execute for nuclei.
// ponytail: real would exec "nuclei -target <target> -jsonl | parser"; stub emits fake finding JSONL.
type NucleiAdapter struct{}

// domainRe matches bare domains like example.com or sub.example.co.uk (no scheme).
var domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// Validate checks target is present and is http(s):// URL or bare domain.
func (a *NucleiAdapter) Validate(_ context.Context, inputs map[string]any) error {
	raw, ok := inputs["target"]
	if !ok || raw == nil {
		return fmt.Errorf("target required")
	}
	target, ok := raw.(string)
	if !ok || strings.TrimSpace(target) == "" {
		return fmt.Errorf("target required")
	}
	target = strings.TrimSpace(target)

	// http(s) URL path
	if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") {
		u, err := url.Parse(target)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid target url: %s", target)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return fmt.Errorf("invalid target url: %s", target)
		}
		return nil
	}

	// bare domain (allow optional port/path by stripping them before match)
	host := target
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if domainRe.MatchString(host) {
		return nil
	}
	return fmt.Errorf("invalid target url: %s", target)
}

// Execute emits a fake nuclei JSONL finding. Real impl would exec nuclei binary and parse JSONL.
// ponytail: ceiling is single stub finding; upgrade to bufio.Scanner over nuclei StdoutPipe with JSON validation.
func (a *NucleiAdapter) Execute(_ context.Context, inputs map[string]any, out chan<- []byte) error {
	target, _ := inputs["target"].(string)
	finding := map[string]any{
		"template-id": "cve-2023-1234",
		"matched-at":  target,
		"info": map[string]any{
			"severity": "high",
			"name":     "Test Vuln",
		},
	}
	// Demonstrate tool-specific parsing: encode then decode to validate JSONL shape before emit.
	b, err := json.Marshal(finding)
	if err != nil {
		return err
	}
	var check map[string]any
	if err := json.Unmarshal(b, &check); err != nil {
		return fmt.Errorf("marshal check failed: %w", err)
	}
	out <- b
	return nil
}
