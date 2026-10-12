package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// fake-arjun stands in for the Arjun CLI in adapter tests. It mirrors the real
// binary's contract: results are written to the -oJ (or -o) path, stdout/stderr
// carry only status markers, and a missing output file means "zero params".
//
// FAKE_ARGS_FILE, when set, receives the exact argv the adapter passed (as a
// JSON array) so tests can assert on buildArjunArgs without altering behavior.
func main() {
	args := os.Args[1:]
	if argsFile := os.Getenv("FAKE_ARGS_FILE"); argsFile != "" {
		raw, err := json.Marshal(args)
		if err != nil {
			fmt.Fprintln(os.Stderr, "marshal args:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(argsFile, raw, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "write args:", err)
			os.Exit(1)
		}
	}

	outFile := ""
	for i, a := range args {
		if (a == "-oJ" || a == "-o") && i+1 < len(args) {
			outFile = args[i+1]
		}
	}

	switch os.Getenv("FAKE_MODE") {
	case "empty":
		// Zero parameters found: Arjun writes NO file and exits 0.
		os.Exit(0)
	case "skip":
		// Refused target: marker on stdout, exit 0, no file.
		fmt.Println("URL doesn't seem to be a webpage. Skipping.")
		os.Exit(0)
	case "fail":
		// Crash: stderr only, nonzero exit, no file.
		fmt.Fprintln(os.Stderr, "AttributeError: 'NoneType' object has no attribute 'get'")
		os.Exit(1)
	case "hang":
		// Simulates Arjun wedging; the adapter's hard timeout must kill it.
		time.Sleep(60 * time.Second)
		os.Exit(0)
	case "many":
		// One URL with 50 parameters: drives the adapter's maxUrls cap.
		params := make([]string, 50)
		for i := range params {
			params[i] = fmt.Sprintf("p%d", i)
		}
		writeResult(outFile, map[string]any{
			"https://example.com/": map[string]any{"params": params, "method": "GET"},
		})
		os.Exit(0)
	default:
		// Two parameters on one URL (fixture mirrors Arjun's exporter shape).
		writeResult(outFile, map[string]any{
			"https://example.com/": map[string]any{
				"params":  []string{"id", "redirect"},
				"method":  "GET",
				"headers": map[string]string{"User-Agent": "x"},
			},
		})
		os.Exit(0)
	}
}

func writeResult(path string, v any) {
	if path == "" {
		return
	}
	raw, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal result:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write result:", err)
		os.Exit(1)
	}
}
