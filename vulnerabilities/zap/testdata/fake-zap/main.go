package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// fake-zap stands in for zap.sh in adapter tests. It reads the automation plan
// passed via -autorun, writes the fixture report to the plan's report job
// destination, and exits with a mode-selected status.
func main() {
	if argsFile := os.Getenv("FAKE_ARGS_FILE"); argsFile != "" {
		raw, _ := json.Marshal(os.Args[1:])
		_ = os.WriteFile(argsFile, raw, 0o644)
	}

	mode := os.Getenv("FAKE_MODE")
	if mode == "noreport" {
		fmt.Fprintln(os.Stderr, "zap: simulated failure before report")
		os.Exit(1)
	}

	reportPath := findReportPath(os.Args[1:])
	if reportPath == "" {
		fmt.Fprintln(os.Stderr, "fake-zap: no -autorun plan with a report job found")
		os.Exit(1)
	}

	content := fixtureReport
	switch mode {
	case "garbage":
		content = "not json at all"
	case "empty":
		content = `{"site": []}`
	}
	if err := os.WriteFile(reportPath, []byte(content), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "fake-zap: write report:", err)
		os.Exit(1)
	}

	switch mode {
	case "error":
		os.Exit(1)
	case "warn":
		os.Exit(2)
	}
}

// findReportPath locates the report job's destination inside the -autorun plan.
func findReportPath(args []string) string {
	planPath := ""
	for i, a := range args {
		if a == "-autorun" && i+1 < len(args) {
			planPath = args[i+1]
		}
	}
	if planPath == "" {
		return ""
	}
	raw, err := os.ReadFile(planPath)
	if err != nil {
		return ""
	}
	var plan struct {
		Jobs []struct {
			Type       string `yaml:"type"`
			Parameters struct {
				ReportDir  string `yaml:"reportDir"`
				ReportFile string `yaml:"reportFile"`
			} `yaml:"parameters"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &plan); err != nil {
		return ""
	}
	for _, j := range plan.Jobs {
		if j.Type == "report" && j.Parameters.ReportFile != "" {
			return filepath.Join(j.Parameters.ReportDir, j.Parameters.ReportFile)
		}
	}
	return ""
}

// fixtureReport mirrors a traditional-json report with two alerts: a high-risk
// XSS with two instances and a low-risk missing-header alert.
const fixtureReport = `{
  "@version": "2.17.0",
  "@generated": "Sat, 19 Sep 2026 08:00:00",
  "created": "2026-09-19T08:00:00Z",
  "site": [
    {
      "@name": "https://example.com",
      "@host": "example.com",
      "@port": "443",
      "@ssl": "true",
      "alerts": [
        {
          "pluginid": "40012",
          "alertRef": "40012",
          "alert": "Cross Site Scripting (Reflected)",
          "name": "Cross Site Scripting (Reflected)",
          "riskcode": "3",
          "confidence": "2",
          "riskdesc": "High (Medium)",
          "desc": "<p>XSS is an attack technique...</p>",
          "instances": [
            {"uri": "https://example.com/search?q=1", "method": "GET", "param": "q", "evidence": "<script>"},
            {"uri": "https://example.com/contact", "method": "POST", "param": "comments", "evidence": "<script>"}
          ],
          "count": "2",
          "solution": "<p>Encode output before rendering.</p>",
          "reference": "<p>https://owasp.org/www-community/attacks/xss/</p><p>https://cwe.mitre.org/data/definitions/79.html</p>",
          "cweid": "79",
          "wascid": "8"
        },
        {
          "pluginid": "10021",
          "alertRef": "10021",
          "alert": "X-Content-Type-Options Header Missing",
          "name": "X-Content-Type-Options Header Missing",
          "riskcode": "1",
          "confidence": "2",
          "riskdesc": "Low (Medium)",
          "desc": "<p>The Anti-MIME-Sniffing header is not set.</p>",
          "instances": [
            {"uri": "https://example.com/", "method": "GET"}
          ],
          "count": "1",
          "solution": "<p>Set the X-Content-Type-Options header to nosniff.</p>",
          "reference": "<p>https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options</p>",
          "cweid": "693",
          "wascid": "15"
        }
      ]
    }
  ]
}`
