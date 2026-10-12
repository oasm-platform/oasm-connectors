package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// fake-dirsearch is a stand-in for the dirsearch CLI used by adapter tests. It
// mirrors the real binary's contract: it writes a JSON report to the -o path
// (never stdout), exits 0 even for an unreachable target or zero results, and
// only fails (nonzero) on a hard error.
func main() {
	// Capture the exact arg vector the adapter passed so tests can assert on
	// it. This must not alter FAKE_MODE behavior.
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

	outFile := outputFile()

	switch os.Getenv("FAKE_MODE") {
	case "empty":
		// Exit 0 with an empty results array: a clean scan that found nothing.
		writeReport(outFile, []byte(`{"results":[]}`))
		os.Exit(0)
	case "fail":
		// Hard error before any report is written: stderr only, nonzero exit.
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "partial-fail":
		// Two results written, then a failure; nonzero exit.
		writeReport(outFile, []byte(`{"results":[{"url":"https://example.com/a","status":200},{"url":"https://example.com/b","status":301}]}`))
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "hang":
		// Simulates dirsearch wedging; the adapter's hard timeout must kill it.
		time.Sleep(60 * time.Second)
		os.Exit(0)
	case "many":
		// 50 unique results: drives the adapter's maxUrls cap.
		type result struct {
			URL    string `json:"url"`
			Status int    `json:"status"`
		}
		rep := struct {
			Results []result `json:"results"`
		}{}
		for i := 0; i < 50; i++ {
			rep.Results = append(rep.Results, result{URL: fmt.Sprintf("https://example.com/n%d", i), Status: 200})
		}
		raw, _ := json.Marshal(rep)
		writeReport(outFile, raw)
		os.Exit(0)
	default:
		// 3 unique http(s) results + 1 duplicate, exit 0.
		writeReport(outFile, []byte(`{"info":{"args":"fake","time":"t"},"results":[{"url":"https://example.com/one","status":200},{"url":"https://example.com/two","status":301},{"url":"https://example.com/three","status":200},{"url":"https://example.com/one","status":200}]}`))
		os.Exit(0)
	}
}

// outputFile returns the value of -o / --output-file from argv ("" if absent).
func outputFile() string {
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "-o" || args[i] == "--output-file" {
			if i+1 < len(args) {
				return args[i+1]
			}
		}
	}
	return ""
}

func writeReport(path string, content []byte) {
	if path == "" {
		return
	}
	_ = os.WriteFile(path, content, 0644)
}
