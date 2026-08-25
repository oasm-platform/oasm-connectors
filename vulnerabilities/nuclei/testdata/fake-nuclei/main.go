package main

import (
	"encoding/json"
	"fmt"
	"os"
)

// fake-nuclei is a stdlib-only test double for the nuclei binary. The adapter
// (adapter.go) execs NUCLEI_BIN with `-target <uri> -jsonl`, reads stdout as
// JSONL, skips non-JSON noise lines, and surfaces the stderr tail on non-zero
// exit. FAKE_MODE selects the canned behavior:
//
//   - "" (default): emit a noise line plus two JSONL findings echoing the target
//   - "empty":      exit 0 with no output
//   - "fail":       write "connection refused" to stderr and exit 1
func main() {
	switch os.Getenv("FAKE_MODE") {
	case "fail":
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "empty":
		return
	}

	target := targetFromArgs(os.Args[1:])

	// Banner/noise line: not valid JSON, the adapter must skip it.
	fmt.Println("[INF] nuclei started scanning " + target)

	emit(finding{
		TemplateID: "cve-2023-1234",
		MatchedAt:  target,
		Info:       info{Name: "Example CVE 2023", Severity: "high"},
		Host:       target,
	})
	emit(finding{
		TemplateID: "cve-2024-5678",
		MatchedAt:  target,
		Info:       info{Name: "Example CVE 2024", Severity: "medium"},
		Host:       target,
	})
}

type finding struct {
	TemplateID string `json:"template-id"`
	MatchedAt  string `json:"matched-at"`
	Info       info   `json:"info"`
	Host       string `json:"host"`
}

type info struct {
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

func emit(f finding) {
	b, err := json.Marshal(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal finding:", err)
		os.Exit(1)
	}
	fmt.Println(string(b))
}

func targetFromArgs(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-target" {
			return args[i+1]
		}
	}
	return ""
}
