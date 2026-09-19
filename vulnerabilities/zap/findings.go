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

// htmlTagRe matches any HTML tag, used to flatten ZAP's HTML descriptions.
var htmlTagRe = regexp.MustCompile(`(?s)<[^>]*>`)

// htmlToText flattens a ZAP HTML blob (desc) into a single plain-text line.
func htmlToText(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	text := htmlTagRe.ReplaceAllString(raw, " ")
	return strings.Join(strings.Fields(html.UnescapeString(text)), " ")
}

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

// alertTags carries the ZAP alert fields that have no dedicated Finding
// column, so they survive in the vulnerability's tag array. The concrete
// affected URI is NOT a tag: it rides on MatchedAt (see instanceURIs).
func alertTags(a zapAlert) []string {
	var tags []string
	if id := strings.TrimSpace(a.PluginID); id != "" {
		tags = append(tags, "pluginid:"+id)
	}
	if ref := strings.TrimSpace(a.AlertRef); ref != "" {
		tags = append(tags, "alertref:"+ref)
	}
	if c := strings.TrimSpace(a.Confidence); c != "" {
		tags = append(tags, "confidence:"+c)
	}
	if w := strings.TrimSpace(a.WASCID); w != "" && w != "0" {
		tags = append(tags, "wascid:"+w)
	}
	if n := strings.TrimSpace(a.Count); n != "" {
		tags = append(tags, "instance-count:"+n)
	}
	return tags
}

// instanceURIs returns every distinct affected URI in report order, falling
// back to the scan target when the alert carried no instances.
func instanceURIs(instances []zapInstance, fallback string) []string {
	seen := make(map[string]struct{}, len(instances))
	var uris []string
	for _, inst := range instances {
		u := strings.TrimSpace(inst.URI)
		if u == "" {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		uris = append(uris, u)
	}
	if len(uris) == 0 {
		return []string{fallback}
	}
	return uris
}

// parseReport maps a traditional-json report onto normalized findings. One
// finding is emitted per affected instance (URI) so each lands as its own
// vulnerability row carrying that URL in affectedUrl. The instance URI travels
// on MatchedAt, which the worker maps onto Vulnerability.affected_url; alert
// fields with no Finding column are preserved as tags (never as tags for the
// affected URL itself, which is a first-class column).
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

			refs := parseReferences(a.Reference)
			solution := strings.TrimSpace(a.Solution)
			description := htmlToText(a.Desc)
			severity := severityFromRiskCode(a.RiskCode)
			var cwe []string
			if c := strings.TrimSpace(a.CWEID); c != "" && c != "0" {
				cwe = []string{c}
			}
			baseTags := alertTags(a)

			for _, uri := range instanceURIs(a.Instances, target) {
				findings = append(findings, connector.Finding{
					Name:        name,
					Severity:    severity,
					Description: description,
					References:  refs,
					Solution:    solution,
					MatchedAt:   uri,
					Host:        host,
					CWEID:       cwe,
					Tags:        append([]string(nil), baseTags...),
					Timestamp:   time.Now(),
				})
			}
		}
	}

	return findings, nil
}
