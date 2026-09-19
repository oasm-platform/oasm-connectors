package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// maxInstanceTags caps how many affected URIs are carried as tags per alert.
// The SDK/worker drops MatchedAt and Transaction, so Tags is the only channel
// that reaches Core — a handful is enough to point at the concrete URLs.
// ponytail: fixed 5; make configurable when users ask for full instance lists.
const maxInstanceTags = 5

// --- Traditional JSON report model (subset ZAP emits) ---

type zapReport struct {
	Site []zapSite `json:"site"`
}

type zapSite struct {
	Name   string     `json:"@name"`
	Host   string     `json:"@host"`
	Alerts []zapAlert `json:"alerts"`
}

type zapAlert struct {
	PluginID   string        `json:"pluginid"`
	AlertRef   string        `json:"alertRef"`
	Alert      string        `json:"alert"`
	Name       string        `json:"name"`
	RiskCode   string        `json:"riskcode"`
	Confidence string        `json:"confidence"`
	Desc       string        `json:"desc"`
	Solution   string        `json:"solution"`
	Reference  string        `json:"reference"`
	CWEID      string        `json:"cweid"`
	WASCID     string        `json:"wascid"`
	Count      string        `json:"count"`
	Instances  []zapInstance `json:"instances"`
}

type zapInstance struct {
	URI      string `json:"uri"`
	Method   string `json:"method"`
	Param    string `json:"param"`
	Evidence string `json:"evidence"`
}

// severityFromRiskCode maps ZAP's numeric risk code onto the SDK severity
// enum. ZAP has no "critical" band; unknown/absent codes become "info".
func severityFromRiskCode(code string) string {
	switch strings.TrimSpace(code) {
	case "0":
		return "info"
	case "1":
		return "low"
	case "2":
		return "medium"
	case "3":
		return "high"
	default:
		return "info"
	}
}

// refParaRe extracts one reference per ZAP <p>...</p> block.
var refParaRe = regexp.MustCompile(`(?is)<p>(.*?)</p>`)

// parseReferences flattens ZAP's HTML reference blob into a clean list.
func parseReferences(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	matches := refParaRe.FindAllStringSubmatch(raw, -1)
	if len(matches) == 0 {
		var out []string
		for _, line := range strings.Split(raw, "\n") {
			if s := strings.TrimSpace(html.UnescapeString(line)); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	var out []string
	for _, m := range matches {
		if s := strings.TrimSpace(html.UnescapeString(m[1])); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// hostFromTarget is the fallback Host when the report omits @host.
func hostFromTarget(target string) string {
	if u, err := url.Parse(target); err == nil && u.Host != "" {
		return u.Host
	}
	return target
}

// parseReport maps a traditional-json report onto normalized findings. One
// finding is emitted per alert (not per instance) to bound the gRPC message
// count; affected URIs ride along as tags.
func parseReport(data []byte, target string) ([]connector.Finding, error) {
	var rep zapReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("parse zap report: %w", err)
	}

	fallbackHost := hostFromTarget(target)
	var findings []connector.Finding

	for _, site := range rep.Site {
		host := strings.TrimSpace(site.Host)
		if host == "" {
			host = fallbackHost
		}
		for _, a := range site.Alerts {
			name := strings.TrimSpace(a.Name)
			if name == "" {
				name = strings.TrimSpace(a.Alert)
			}
			if name == "" {
				continue
			}

			matchedAt := target
			if len(a.Instances) > 0 {
				if u := strings.TrimSpace(a.Instances[0].URI); u != "" {
					matchedAt = u
				}
			}

			f := connector.Finding{
				Name:       name,
				Severity:   severityFromRiskCode(a.RiskCode),
				References: parseReferences(a.Reference),
				Solution:   strings.TrimSpace(a.Solution),
				MatchedAt:  matchedAt,
				Host:       host,
				Timestamp:  time.Now(),
			}

			if cwe := strings.TrimSpace(a.CWEID); cwe != "" && cwe != "0" {
				f.CWEID = []string{cwe}
			}

			if id := strings.TrimSpace(a.PluginID); id != "" {
				f.Tags = append(f.Tags, "pluginid:"+id)
			}
			if c := strings.TrimSpace(a.Confidence); c != "" {
				f.Tags = append(f.Tags, "confidence:"+c)
			}
			if n := strings.TrimSpace(a.Count); n != "" {
				f.Tags = append(f.Tags, "instance-count:"+n)
			}
			for i, inst := range a.Instances {
				if i >= maxInstanceTags {
					break
				}
				if u := strings.TrimSpace(inst.URI); u != "" {
					f.Tags = append(f.Tags, "affected-uri:"+u)
				}
			}

			findings = append(findings, f)
		}
	}

	return findings, nil
}
