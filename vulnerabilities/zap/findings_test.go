package main

import (
	"strings"
	"testing"
)

func TestSeverityFromRiskCode(t *testing.T) {
	cases := map[string]string{
		"0":     "info",
		"1":     "low",
		"2":     "medium",
		"3":     "high",
		"":      "info",
		"9":     "info",
		"3 ":    "high",
		"weird": "info",
	}
	for in, want := range cases {
		if got := severityFromRiskCode(in); got != want {
			t.Errorf("severityFromRiskCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseReferences(t *testing.T) {
	got := parseReferences("<p>https://a.example</p><p>https://b.example&amp;x=1</p>")
	if len(got) != 2 {
		t.Fatalf("expected 2 references, got %d: %v", len(got), got)
	}
	if got[0] != "https://a.example" {
		t.Errorf("ref[0] = %q", got[0])
	}
	if got[1] != "https://b.example&x=1" {
		t.Errorf("ref[1] unescaped = %q", got[1])
	}

	if refs := parseReferences(""); refs != nil {
		t.Errorf("empty input should yield nil, got %v", refs)
	}

	plain := parseReferences("https://plain.example")
	if len(plain) != 1 || plain[0] != "https://plain.example" {
		t.Errorf("plain reference = %v", plain)
	}
}

const reportFixture = `{
  "site": [
    {
      "@name": "https://example.com",
      "@host": "example.com",
      "alerts": [
        {
          "pluginid": "40012",
          "name": "Cross Site Scripting (Reflected)",
          "riskcode": "3",
          "confidence": "2",
          "desc": "<p>XSS is an attack technique...</p>",
          "solution": "<p>Encode output.</p>",
          "reference": "<p>https://owasp.org/xss</p>",
          "cweid": "79",
          "count": "2",
          "instances": [
            {"uri": "https://example.com/search?q=1"},
            {"uri": "https://example.com/contact"}
          ]
        },
        {
          "pluginid": "10021",
          "alert": "X-Content-Type-Options Header Missing",
          "riskcode": "1",
          "cweid": "0",
          "instances": [{"uri": "https://example.com/"}]
        }
      ]
    }
  ]
}`

func TestParseReport_MapsAlerts(t *testing.T) {
	findings, err := parseReport([]byte(reportFixture), "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// One finding per affected instance: 2 for the XSS alert + 1 for the
	// header alert.
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	f := findings[0]
	if f.Name != "Cross Site Scripting (Reflected)" {
		t.Errorf("Name = %q", f.Name)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q, want high", f.Severity)
	}
	if f.Host != "example.com" {
		t.Errorf("Host = %q", f.Host)
	}
	if f.MatchedAt != "https://example.com/search?q=1" {
		t.Errorf("MatchedAt = %q", f.MatchedAt)
	}
	if len(f.CWEID) != 1 || f.CWEID[0] != "79" {
		t.Errorf("CWEID = %v", f.CWEID)
	}
	if f.Solution != "<p>Encode output.</p>" {
		t.Errorf("Solution = %q", f.Solution)
	}
	if f.Description != "XSS is an attack technique..." {
		t.Errorf("Description = %q", f.Description)
	}
	if len(f.References) != 1 || f.References[0] != "https://owasp.org/xss" {
		t.Errorf("References = %v", f.References)
	}
	if !hasTag(f.Tags, "pluginid:40012") {
		t.Errorf("missing pluginid tag: %v", f.Tags)
	}
	if !hasTag(f.Tags, "confidence:2") {
		t.Errorf("missing confidence tag: %v", f.Tags)
	}
	if !hasTag(f.Tags, "instance-count:2") {
		t.Errorf("missing instance-count tag: %v", f.Tags)
	}
	// The affected URI is a first-class column now, never a tag.
	for _, tag := range f.Tags {
		if strings.HasPrefix(tag, "affected-uri:") {
			t.Errorf("affected URI must not be a tag: %v", f.Tags)
		}
	}

	// Second instance of the same alert becomes its own finding with its own
	// affected URL.
	if findings[1].Name != "Cross Site Scripting (Reflected)" ||
		findings[1].MatchedAt != "https://example.com/contact" {
		t.Errorf("second instance = %q @ %q", findings[1].Name, findings[1].MatchedAt)
	}

	// Third alert falls back to the "alert" field for its name, uses the
	// "low" band, and drops the zero CWE id.
	third := findings[2]
	if third.Name != "X-Content-Type-Options Header Missing" {
		t.Errorf("third Name = %q", third.Name)
	}
	if third.Severity != "low" {
		t.Errorf("third Severity = %q", third.Severity)
	}
	if third.CWEID != nil {
		t.Errorf("third CWEID should be nil for id 0, got %v", third.CWEID)
	}
	if third.MatchedAt != "https://example.com/" {
		t.Errorf("third MatchedAt = %q", third.MatchedAt)
	}
}

func TestParseReport_EmptySite(t *testing.T) {
	findings, err := parseReport([]byte(`{"site": []}`), "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestParseReport_MalformedErrors(t *testing.T) {
	if _, err := parseReport([]byte("not json"), "https://example.com"); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestParseReport_SkipsNamelessAlert(t *testing.T) {
	data := `{"site":[{"@host":"example.com","alerts":[{"pluginid":"1","riskcode":"2"}]}]}`
	findings, err := parseReport([]byte(data), "https://example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("nameless alert should be skipped, got %d", len(findings))
	}
}

func TestParseReport_FallsBackToTargetHost(t *testing.T) {
	data := `{"site":[{"alerts":[{"name":"N","riskcode":"0","instances":[]}]}]}`
	findings, err := parseReport([]byte(data), "https://fallback.example")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Host != "fallback.example" {
		t.Errorf("Host = %q, want fallback.example", findings[0].Host)
	}
	if findings[0].MatchedAt != "https://fallback.example" {
		t.Errorf("MatchedAt = %q", findings[0].MatchedAt)
	}
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if t == want {
			return true
		}
	}
	return false
}
