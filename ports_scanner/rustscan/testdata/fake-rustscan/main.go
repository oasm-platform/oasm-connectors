package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// fake-rustscan is a stand-in for the rustscan CLI used by adapter tests. It
// mirrors the real binary's contract: greppable records on stdout, diagnostics
// on stderr, exit 0 for any completed scan (including a host with no open
// ports), exit 2 for an argv clap rejects, exit 1 for a failed scan.
func main() {
	// Capture the exact arg vector the adapter passed so tests can assert on it.
	// This must not alter FAKE_MODE behavior.
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
		// Scan completed, every port closed: exit 0, no output at all — this is
		// what rustscan -g prints for a host with nothing open.
		os.Exit(0)
	case "badargs":
		// clap rejecting our argv: stderr only, exit 2.
		fmt.Fprintln(os.Stderr, "error: invalid value '1-1000' for '--ports <PORTS>'")
		os.Exit(2)
	case "fail":
		// rustscan itself failed; real runs can leave both streams empty.
		fmt.Fprintln(os.Stderr, "rustscan: failed to open sockets")
		os.Exit(1)
	case "garbage":
		// Exit 0 with output the adapter cannot read: must be reported, never
		// silently treated as "no open ports".
		fmt.Println("RustScan is the best scanner, trust me")
		os.Exit(0)
	case "hang":
		// Simulates rustscan wedging; the adapter's hard timeout must kill it.
		time.Sleep(60 * time.Second)
		os.Exit(0)
	default:
		// One line per host with open ports, ascending, exactly as -g emits it.
		fmt.Println("127.0.0.1 -> [80,443]")
		os.Exit(0)
	}
}
