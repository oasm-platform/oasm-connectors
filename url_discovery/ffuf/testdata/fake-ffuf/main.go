package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// fake-ffuf is a stand-in for the ffuf CLI used by adapter tests. It mirrors the
// real binary's -json contract: one JSON object per stdout line.
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
		// Fatal failure: stderr only, nonzero exit, no stdout.
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "partial-fail":
		// Some matches streamed before a failure; nonzero exit.
		emit(0, "https://example.com/a")
		emit(1, "https://example.com/b")
		fmt.Fprintln(os.Stderr, "connection refused")
		os.Exit(1)
	case "hang":
		// Simulates ffuf wedging; the adapter's hard timeout must kill it.
		time.Sleep(60 * time.Second)
		os.Exit(0)
	case "many":
		// Endless unique match stream: drives the adapter's maxUrls cap.
		for i := 0; ; i++ {
			emit(i, fmt.Sprintf("https://example.com/n%d", i))
			time.Sleep(time.Millisecond)
		}
	default:
		// 3 unique matches + 1 duplicate + 1 blank + 1 non-http `url`, exit 0.
		// The base64 `input` field is present as the real binary emits it but
		// must never be parsed by the adapter.
		emit(0, "https://example.com/one")
		emit(1, "https://example.com/two")
		emit(2, "https://example.com/three")
		emit(3, "https://example.com/one") // duplicate -> deduped
		fmt.Println("")                    // blank line -> skipped
		emit(4, "ftp://example.com/x")     // non-http -> skipped
		os.Exit(0)
	}
}

// emit writes one real-shaped ffuf -json line: base64 `input`, numeric
// position/status, and the matched `url`/`host`.
func emit(position int, url string) {
	input := base64.StdEncoding.EncodeToString([]byte("FUZZ"))
	host := "example.com"
	line := fmt.Sprintf(`{"input":{"FUZZ":%q},"position":%d,"status":200,"length":1234,"words":5,"lines":10,"content-type":"text/html","redirectlocation":"","scraper":{},"duration":1000000,"resultfile":"","url":%q,"host":%q}`,
		input, position, url, host)
	fmt.Println(line)
}
