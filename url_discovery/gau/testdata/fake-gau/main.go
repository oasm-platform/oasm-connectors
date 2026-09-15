package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// fake-gau is a stand-in for the gau (GetAllUrls) CLI used by adapter tests.
// It mirrors the real binary's contract: one discovered URL per stdout line.
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

	switch os.Getenv("FAKE_MODE") {
	case "empty":
		// Exit 0, no output: a clean scan that found nothing.
		os.Exit(0)
	case "fail":
		// Fatal provider failure: stderr only, nonzero exit, no stdout.
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "partial-fail":
		// Some URLs streamed before a provider failed; nonzero exit.
		fmt.Println("https://example.com/a")
		fmt.Println("https://example.com/b")
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "hang":
		// Simulates gau wedging on a dead provider; the adapter's hard
		// timeout must kill the process.
		time.Sleep(60 * time.Second)
		os.Exit(0)
	default:
		// 3 unique URLs + 1 duplicate + 1 blank line, exit 0.
		fmt.Println("https://example.com/one")
		fmt.Println("https://example.com/two")
		fmt.Println("")
		fmt.Println("https://example.com/three")
		fmt.Println("https://example.com/one")
		os.Exit(0)
	}
}
