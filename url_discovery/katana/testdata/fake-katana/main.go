package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// fake-katana is a stand-in for the katana CLI used by adapter tests. It
// mirrors the real binary's contract: one discovered URL per stdout line in
// plain (non-JSON) silent mode, and the exit-code quirks documented in the
// adapter (unreachable target -> 0, runner init failure -> 0 with a stderr
// marker, unknown flag -> 2).
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
	// The adapter deletes its -mr/-fr pattern files once katana exits, so the
	// fake copies their lines out while they still exist. It does NOT apply
	// the patterns, so the tests also prove the adapter filters katana's
	// output itself.
	if patternsFile := os.Getenv("FAKE_PATTERNS_FILE"); patternsFile != "" {
		patterns := map[string][]string{}
		args := os.Args[1:]
		for i := 0; i+1 < len(args); i++ {
			if args[i] != "-mr" && args[i] != "-fr" {
				continue
			}
			raw, err := os.ReadFile(args[i+1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "read pattern file:", err)
				os.Exit(1)
			}
			patterns[args[i]] = strings.Split(string(raw), "\n")
		}
		raw, err := json.Marshal(patterns)
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal patterns:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(patternsFile, raw, 0644); err != nil {
			fmt.Fprintln(os.Stderr, "write patterns:", err)
			os.Exit(1)
		}
	}

	switch os.Getenv("FAKE_MODE") {
	case "empty":
		// Exit 0, no output: a clean crawl that found nothing.
		os.Exit(0)
	case "fail":
		// Fatal network failure: stderr only, nonzero exit, no stdout.
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "partial-fail":
		// Some URLs streamed before a failure; nonzero exit.
		fmt.Println("https://example.com/a")
		fmt.Println("https://example.com/b")
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "runner-fail":
		// Runner initialization failure: katana prints this marker to stderr
		// and exits 0 — the exit code is NOT the signal, the marker is.
		fmt.Fprintln(os.Stderr, "could not create runner: proxy not initialized")
		os.Exit(0)
	case "hang":
		// Simulates katana wedging; the adapter's hard timeout must kill it.
		time.Sleep(60 * time.Second)
		os.Exit(0)
	case "pages":
		// A mix of page kinds for the matchRegex / filterRegex tests.
		fmt.Println("https://example.com/login")
		fmt.Println("https://example.com/admin/login?next=%2F")
		fmt.Println("https://example.com/about")
		fmt.Println("https://example.com/static/login.css")
		fmt.Println("https://example.com/#/admin")
		os.Exit(0)
	case "many":
		// Endless URL stream with no repeats: drives the adapter's maxUrls cap.
		for i := 0; ; i++ {
			fmt.Printf("https://example.com/n%d\n", i)
			time.Sleep(time.Millisecond)
		}
	default:
		// 3 unique http(s) URLs + 1 blank + 1 ftp + 1 mailto + 1 duplicate.
		// katana emits non-http schemes by default (measured), so the adapter
		// must filter them out; the duplicate proves client-side dedupe.
		fmt.Println("https://example.com/one")
		fmt.Println("https://example.com/two")
		fmt.Println("")
		fmt.Println("ftp://ftp.example.com/pub")
		fmt.Println("mailto:iana@iana.org")
		fmt.Println("https://example.com/three")
		fmt.Println("https://example.com/one")
		os.Exit(0)
	}
}
