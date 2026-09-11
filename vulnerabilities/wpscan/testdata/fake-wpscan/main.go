package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	// Consume CLI flags (--url, --format, --no-banner, --random-user-agent).
	// We don't validate them — just consume os.Args for realism.
	_ = os.Args

	// When FAKE_ARGS_FILE is set, capture the exact arg vector the adapter
	// passed so tests can assert on it. Do not alter FAKE_MODE behavior.
	if argsFile := os.Getenv("FAKE_ARGS_FILE"); argsFile != "" {
		raw, err := json.Marshal(os.Args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal args:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(argsFile, raw, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "write args:", err)
			os.Exit(1)
		}
	}

	mode := os.Getenv("FAKE_MODE")

	switch mode {
	case "fail":
		// Unparseable invocation error: no JSON on stdout.
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "garbage":
		// Exit 1 (CLI_OPTION_ERROR) with non-JSON stdout + stderr tail.
		fmt.Print("this is not json at all")
		fmt.Fprintln(os.Stderr, "unknown option --bogus")
		os.Exit(1)
	case "abort":
		// Exit 4 (ERROR): target is up but not WordPress; stdout still JSON.
		fmt.Print(abortOutput)
		os.Exit(4)
	case "notconfigured":
		// Exit 4 (ERROR) install mode; stdout still JSON.
		fmt.Print(notConfiguredOutput)
		os.Exit(4)
	case "vuln5":
		// Exit 5 (VULNERABLE): success, findings present.
		fmt.Print(vulnerableOutput)
		os.Exit(5)
	case "all":
		// Exit 0, vulnerabilities in all 7 locations.
		fmt.Print(allLocationsOutput)
		os.Exit(0)
	case "empty":
		fmt.Print(emptyOutput)
	default:
		fmt.Print(normalOutput)
	}
}

// normalOutput mirrors a realistic (token-less) scan: core version and a plugin
// carry vulnerabilities. Titles match the historical fixture so the existing
// streaming test keeps asserting the same names.
const normalOutput = `{
  "target_url": "https://example.com",
  "version": {
    "number": "5.4.2",
    "status": "insecure",
    "vulnerabilities": [
      {
        "title": "XSS in Search Form",
        "cvss": {"score": "6.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"},
        "fixed_in": "5.4.3",
        "references": {"url": ["https://example.com/advisory/1"]}
      }
    ]
  },
  "main_theme": null,
  "plugins": {
    "akismet": {
      "slug": "akismet",
      "version": {"number": "4.1.2", "vulnerabilities": []},
      "vulnerabilities": [
        {
          "title": "Open Redirect in Akismet",
          "cvss": {"score": 3.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N"},
          "fixed_in": "4.1.3",
          "references": {"cve": ["CVE-2024-0001"]}
        }
      ]
    }
  },
  "themes": {},
  "vuln_api": {"error": "No WPScan API Token given"}
}`

const emptyOutput = `{
  "target_url": "https://clean.example.com",
  "version": {"number": "6.4.2", "status": "latest", "vulnerabilities": []},
  "main_theme": null,
  "plugins": {},
  "themes": {},
  "vuln_api": {"error": "No WPScan API Token given"}
}`

const abortOutput = `{
  "scan_aborted": "The remote website is up, but does not seem to be running WordPress.",
  "target_url": "https://example.com/"
}`

const notConfiguredOutput = `{
  "not_fully_configured": "The Website is not fully configured and currently in install mode. Create a new admin user at http://example.com/wp-admin/install.php"
}`

// vulnerableOutput exercises core + plugin + main_theme locations on exit 5.
const vulnerableOutput = `{
  "target_url": "https://example.com",
  "version": {
    "number": "5.4.2",
    "status": "insecure",
    "vulnerabilities": [
      {"title": "Core RCE", "cvss": {"score": "9.8", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
    ]
  },
  "main_theme": {
    "slug": "twentytwenty",
    "version": {"number": "1.5", "vulnerabilities": [
      {"title": "Theme XSS", "cvss": {"score": 4.8, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}}
    ]},
    "vulnerabilities": [
      {"title": "Theme File Inclusion", "cvss": {"score": "8.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"}}
    ]
  },
  "plugins": {
    "contact-form-7": {
      "slug": "contact-form-7",
      "version": {"number": "5.3", "vulnerabilities": [
        {"title": "CF7 Unrestricted Upload", "cvss": {"score": "9.8", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
      ]},
      "vulnerabilities": [
        {"title": "CF7 Stored XSS", "cvss": {"score": "6.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"}}
      ]
    }
  },
  "themes": {},
  "vuln_api": {"error": "No WPScan API Token given"}
}`

// allLocationsOutput places exactly one vulnerability at each of the 7 real
// locations: core, plugin, plugin.version, theme, theme.version, main_theme,
// main_theme.version.
const allLocationsOutput = `{
  "target_url": "https://example.com",
  "version": {
    "number": "5.4.2",
    "vulnerabilities": [
      {"title": "Loc1 Core", "cvss": {"score": "9.0"}}
    ]
  },
  "main_theme": {
    "slug": "main",
    "version": {"number": "1.0", "vulnerabilities": [
      {"title": "Loc7 MainThemeVersion", "cvss": {"score": "6.9"}}
    ]},
    "vulnerabilities": [
      {"title": "Loc6 MainTheme", "cvss": {"score": "4.0"}}
    ]
  },
  "plugins": {
    "p1": {
      "slug": "p1",
      "version": {"number": "1.0", "vulnerabilities": [
        {"title": "Loc3 PluginVersion", "cvss": {"score": "3.9"}}
      ]},
      "vulnerabilities": [
        {"title": "Loc2 Plugin", "cvss": {"score": "0.1"}}
      ]
    }
  },
  "themes": {
    "t1": {
      "slug": "t1",
      "version": {"number": "1.0", "vulnerabilities": [
        {"title": "Loc5 ThemeVersion", "cvss": {"score": "8.9"}}
      ]},
      "vulnerabilities": [
        {"title": "Loc4 Theme", "cvss": {"score": "7.0"}}
      ]
    }
  }
}`
