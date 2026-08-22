package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeManifest(t *testing.T, dir, content string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "manifest.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const validYAML = `name: nuclei
version: 3.3.0
image: ghcr.io/open-asm/connector-nuclei:3.3.0
capabilities: [vulnerabilities]
`

func TestDiscoverCategoryLayout(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, filepath.Join(root, "vulnerabilities", "nuclei"), validYAML)
	entries, err := discoverManifests(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
}

func TestSkipNonCategoryDirs(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, filepath.Join(root, "sdk", "fake"), validYAML) // must be skipped
	writeManifest(t, filepath.Join(root, "vulnerabilities", "nuclei"), validYAML)
	entries, err := discoverManifests(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || !strings.Contains(entries[0], filepath.Join("vulnerabilities", "nuclei")) {
		t.Fatalf("expected only vulnerabilities/nuclei, got %v", entries)
	}
}

func TestValidateRejectsBadName(t *testing.T) {
	m := &Manifest{Name: "Bad_Name!", Version: "1.0.0", Image: "x", Capabilities: []string{"c"}}
	if err := validate(m, "test"); err == nil {
		t.Fatal("expected error for bad name")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	root := t.TempDir()
	p := writeManifest(t, filepath.Join(root, "vulnerabilities", "nuclei"), validYAML+"unknownField: 1\n")
	if _, err := loadManifest(p); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestRunDetectsDuplicateNames(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "manifest.json")
	writeManifest(t, filepath.Join(root, "vulnerabilities", "a"), validYAML)
	writeManifest(t, filepath.Join(root, "discovery", "a"), validYAML)
	if err := run(root, out); err == nil {
		t.Fatal("expected duplicate-name error")
	}
}
