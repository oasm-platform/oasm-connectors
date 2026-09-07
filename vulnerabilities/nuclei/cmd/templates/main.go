package main

// cmd/templates is a build-time-only helper that bakes nuclei-templates into the
// directory given as the first argument. It is NOT compiled into the connector
// binary (the Dockerfile runs it via `go run` in the builder stage only).
//
// Usage: go run ./cmd/templates <dir>

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/templates <dir>")
		os.Exit(1)
	}
	dir := os.Args[1]
	config.DefaultConfig.SetTemplatesDir(dir)
	installer.HideProgressBar = true
	if err := (&installer.TemplateManager{}).FreshInstallIfNotExists(); err != nil {
		fmt.Fprintln(os.Stderr, "template install failed:", err)
		os.Exit(1)
	}
	// Verify non-empty (mirrors the old Dockerfile `test -n "$(ls -A ...)"` guard).
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "templates dir empty or unreadable after install: %s (err=%v)\n", dir, err)
		os.Exit(1)
	}
	fmt.Printf("templates baked at %s: %d entries\n", dir, len(entries))
}
