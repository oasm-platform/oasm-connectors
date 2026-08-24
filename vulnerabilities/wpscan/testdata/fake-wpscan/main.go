package main

import (
	"fmt"
	"os"
)

func main() {
	// Consume CLI flags (--url, --format, --no-banner, --random-user-agent).
	// We don't validate them — just consume os.Args for realism.
	_ = os.Args

	mode := os.Getenv("FAKE_MODE")

	switch mode {
	case "fail":
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "empty":
		fmt.Print(emptyOutput)
	default:
		fmt.Print(normalOutput)
	}
}

const normalOutput = `{
  "target": {
    "url": "https://example.com"
  },
  "vulnerabilities": {
    "XSS in Search Form": [
      {
        "title": "XSS in Search Form",
        "severity": "Medium",
        "references": {
          "url": ["https://example.com/advisory/1"]
        }
      }
    ]
  },
  "plugins": {
    "akismet": {
      "vulnerabilities": {
        "Open Redirect": [
          {
            "title": "Open Redirect in Akismet",
            "severity": "Low",
            "references": {
              "cve": ["CVE-2024-0001"]
            }
          }
        ]
      }
    }
  },
  "themes": {},
  "version": null
}`

const emptyOutput = `{
  "target": {
    "url": "https://clean.example.com"
  },
  "vulnerabilities": {},
  "plugins": {},
  "themes": {},
  "version": null
}`
