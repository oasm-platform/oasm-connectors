package main

import (
	"encoding/base64"
	"encoding/json"
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

// pngBytes is a small non-empty payload with PNG magic for realism; content
// beyond the magic bytes is irrelevant to the embedding logic.
var pngBytes = append([]byte{0x89}, []byte("PNG\r\n\x1a\nfake-image-data")...)

func TestRunEmbedsLogoBase64(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vulnerabilities", "nuclei")
	writeManifest(t, dir, validYAML)
	logoPath := filepath.Join(dir, "logo.png")
	if err := os.WriteFile(logoPath, pngBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "manifest.json")
	if err := run(root, out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Connectors []map[string]any `json:"connectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Connectors) != 1 {
		t.Fatalf("expected 1 connector, got %d", len(doc.Connectors))
	}
	want := base64.StdEncoding.EncodeToString(pngBytes)
	got, ok := doc.Connectors[0]["logo"].(string)
	if !ok {
		t.Fatalf("connector object has no string \"logo\" key: %v", doc.Connectors[0])
	}
	if got != want {
		t.Fatalf("logo mismatch:\n got  %q\n want %q", got, want)
	}
}

func TestRunOmitsLogoWhenMissing(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, filepath.Join(root, "vulnerabilities", "nuclei"), validYAML)
	out := filepath.Join(root, "manifest.json")
	if err := run(root, out); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Connectors []map[string]any `json:"connectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Connectors) != 1 {
		t.Fatalf("expected 1 connector, got %d", len(doc.Connectors))
	}
	if v, present := doc.Connectors[0]["logo"]; present {
		t.Fatalf("expected no \"logo\" key when logo.png absent, got %q", v)
	}
}
