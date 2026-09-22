// Command fake-nikto is a test double for nikto.pl: it consumes the CLI flags
// the adapter passes and prints canned stdout per FAKE_MODE, so adapter tests
// need neither nikto nor Perl nor a network.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

func main() {
	_ = os.Args

	// Capture the exact arg vector for argv assertions.
	if argsFile := os.Getenv("FAKE_ARGS_FILE"); argsFile != "" {
		raw, err := json.Marshal(os.Args[1:])
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal args:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(argsFile, raw, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write args:", err)
			os.Exit(1)
		}
	}

	// Capture the generated -config body so tests can assert on it.
	if cfgFile := os.Getenv("FAKE_CONFIG_COPY"); cfgFile != "" {
		if src, err := readConfigArg(os.Args[1:]); err == nil {
			_ = os.WriteFile(cfgFile, []byte(src), 0o644)
		}
	}

	switch os.Getenv("FAKE_MODE") {
	case "fail":
		// Config/database error: no results, exit 1.
		fmt.Fprintln(os.Stderr, "ERROR: Can't find/read required file \"db_tests\"")
		os.Exit(1)
	case "partial-fail":
		// Results then a hard error: exit 1 with output already emitted.
		fmt.Print(normalOutput)
		fmt.Fprintln(os.Stderr, "ERROR: Can't open \"udb_tests\"")
		os.Exit(1)
	case "empty":
		fmt.Print(emptyOutput)
	case "unreachable":
		fmt.Print(unreachableOutput)
	case "hang":
		time.Sleep(60 * time.Second)
	case "many":
		for i := 0; ; i++ {
			fmt.Printf("+ [000024] /path%d: Synthetic issue %d. See: CVE-2000-0709\n", i, i)
			time.Sleep(time.Millisecond)
		}
	case "slow-many":
		// A long-running scan: findings trickle out forever. Used to prove the
		// adapter imposes no ceiling of its own — only the caller's context can
		// end this.
		for i := 0; ; i++ {
			fmt.Printf("+ [000024] /path%d: Synthetic issue %d. See: CVE-2000-0709\n", i, i)
			time.Sleep(50 * time.Millisecond)
		}
	case "norefs":
		fmt.Print(noRefsOutput)
	default:
		fmt.Print(normalOutput)
	}
}

// readConfigArg extracts the value following -config.
func readConfigArg(args []string) (string, error) {
	for i, a := range args {
		if a == "-config" && i+1 < len(args) {
			raw, err := os.ReadFile(args[i+1])
			return string(raw), err
		}
	}
	return "", fmt.Errorf("-config not found")
}

// normalOutput mirrors a real scan: banner, target info, two results (one with
// advisories, one without), and the closing summary. Only the "+ [id] ..."
// lines are results.
const normalOutput = `- Nikto v2.6.1
---------------------------------------------------------------------------
+ Target IP:          93.184.216.34
+ Target Hostname:    example.com
+ Target Port:        443
+ Start Time:         2026-07-31 16:17:55 (GMT0)
---------------------------------------------------------------------------
+ Server: nginx/1.24.0
+ [000024] /_vti_bin/shtml.exe: Attackers may be able to crash FrontPage by requesting a DOS device. See: CVE-2000-0709
+ [999957] /admin/: Admin login page found.
+ [000038] /~root/: Allowed to browse root's home directory. See: CVE-2001-1013 https://nvd.nist.gov/vuln/detail/CVE-2001-1013
+ 2 host(s) tested
`

const emptyOutput = `- Nikto v2.6.1
---------------------------------------------------------------------------
+ Target IP:          93.184.216.34
+ Target Hostname:    example.com
+ Target Port:        443
---------------------------------------------------------------------------
+ Server: nginx/1.24.0
+ 1 host(s) tested
`

const unreachableOutput = `- Nikto v2.6.1
---------------------------------------------------------------------------
+ [FAIL] Unable to connect to example.com:443. No web server found on example.com:443
+ 1 host(s) tested
`

const noRefsOutput = `- Nikto v2.6.1
---------------------------------------------------------------------------
+ [000024] /backup.zip: Backup file found, source code disclosure.
+ 1 host(s) tested
`
