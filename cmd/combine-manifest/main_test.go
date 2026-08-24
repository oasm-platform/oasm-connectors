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

const validYAML = `name: "Nuclei Scanner"
slug: nuclei
version: 3.3.0
image: ghcr.io/open-asm/connector-nuclei:3.3.0
author: "oasm"
license: free
shortDescription: "Fast template-based vulnerability scanner"
description: "Runs ProjectDiscovery Nuclei template-based scans against a target URL."
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

func TestValidateRejectsEmptyName(t *testing.T) {
	m := &Manifest{Name: "   ", Slug: "nuclei", Version: "1.0.0", Image: "x",
		ShortDescription: "short", Description: "long", Capabilities: []string{"c"}}
	err := validate(m, "test")
	if err == nil {
		t.Fatal("expected error for empty/whitespace-only name")
	}
	if !strings.Contains(err.Error(), "name required") {
		t.Fatalf("expected error mentioning name required, got %q", err.Error())
	}
}

func TestValidateRejectsMissingSlug(t *testing.T) {
	m := &Manifest{Name: "Nuclei Scanner", Version: "3.3.0", Image: "x",
		ShortDescription: "short", Description: "long", Capabilities: []string{"vulnerabilities"}}
	err := validate(m, "test")
	if err == nil {
		t.Fatal("expected error for missing slug")
	}
	if !strings.Contains(err.Error(), "slug required") {
		t.Fatalf("expected error mentioning slug required, got %q", err.Error())
	}
}

func TestValidateRejectsBadSlug(t *testing.T) {
	for _, bad := range []string{"Nuclei", "bad_slug", "nuclei scanner"} {
		m := &Manifest{Name: "Nuclei Scanner", Slug: bad, Version: "3.3.0", Image: "x",
			ShortDescription: "short", Description: "long", Capabilities: []string{"vulnerabilities"}}
		err := validate(m, "test")
		if err == nil {
			t.Fatalf("expected error for bad slug %q", bad)
		}
		if !strings.Contains(err.Error(), "invalid slug") {
			t.Fatalf("slug %q: expected error mentioning invalid slug, got %q", bad, err.Error())
		}
	}
}

func TestValidateAllowsSpacedUppercaseName(t *testing.T) {
	m := &Manifest{Name: "Nuclei Scanner v2", Slug: "nuclei", Version: "3.3.0", Image: "x",
		ShortDescription: "short", Description: "long", Capabilities: []string{"vulnerabilities"},
		Author: "oasm", License: "free"}
	if err := validate(m, "test"); err != nil {
		t.Fatalf("spaced uppercase display name should be valid, got %v", err)
	}
}

func TestValidateRejectsMissingDescription(t *testing.T) {
	m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x",
		ShortDescription: "short", Capabilities: []string{"vulnerabilities"}}
	err := validate(m, "test")
	if err == nil {
		t.Fatal("expected error for missing description")
	}
	if !strings.Contains(err.Error(), "description required") {
		t.Fatalf("expected error mentioning description required, got %q", err.Error())
	}
}

func TestValidateRejectsMissingShortDescription(t *testing.T) {
	m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x",
		Description: "long description", Capabilities: []string{"vulnerabilities"}}
	err := validate(m, "test")
	if err == nil {
		t.Fatal("expected error for missing shortDescription")
	}
	if !strings.Contains(err.Error(), "shortDescription required") {
		t.Fatalf("expected error mentioning shortDescription required, got %q", err.Error())
	}
}

func TestValidateRejectsMissingAuthor(t *testing.T) {
	m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x", License: "free",
		ShortDescription: "short", Description: "long description",
		Capabilities: []string{"vulnerabilities"}}
	err := validate(m, "test")
	if err == nil {
		t.Fatal("expected error for missing author")
	}
	if !strings.Contains(err.Error(), "author required") {
		t.Fatalf("expected error mentioning author required, got %q", err.Error())
	}
}

func TestValidateRejectsMissingLicense(t *testing.T) {
	m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x", Author: "oasm",
		ShortDescription: "short", Description: "long description",
		Capabilities: []string{"vulnerabilities"}}
	err := validate(m, "test")
	if err == nil {
		t.Fatal("expected error for missing license")
	}
	if !strings.Contains(err.Error(), "license required") {
		t.Fatalf("expected error mentioning license required, got %q", err.Error())
	}
}

// TestLoadAndRunEmitDescriptions proves loadManifest parses both description
// fields and run() emits them as JSON keys on each connector object.
func TestLoadAndRunEmitDescriptions(t *testing.T) {
	root := t.TempDir()
	writeManifest(t, filepath.Join(root, "vulnerabilities", "nuclei"), validYAML)

	m, err := loadManifest(filepath.Join(root, "vulnerabilities", "nuclei", "manifest.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if m.ShortDescription != "Fast template-based vulnerability scanner" {
		t.Fatalf("ShortDescription not parsed: %q", m.ShortDescription)
	}
	if m.Description != "Runs ProjectDiscovery Nuclei template-based scans against a target URL." {
		t.Fatalf("Description not parsed: %q", m.Description)
	}
	if m.Slug != "nuclei" {
		t.Fatalf("Slug not parsed: %q", m.Slug)
	}
	if m.Author != "oasm" {
		t.Fatalf("Author not parsed: %q", m.Author)
	}
	if m.License != "free" {
		t.Fatalf("License not parsed: %q", m.License)
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
	for _, key := range []string{"description", "shortDescription", "author", "license", "slug"} {
		v, ok := doc.Connectors[0][key].(string)
		if !ok || v == "" {
			t.Fatalf("connector object missing non-empty %q key: %v", key, doc.Connectors[0])
		}
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	root := t.TempDir()
	p := writeManifest(t, filepath.Join(root, "vulnerabilities", "nuclei"), validYAML+"unknownField: 1\n")
	if _, err := loadManifest(p); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

// TestRunDetectsDuplicateSlugs proves run() keys uniqueness on Slug, not Name:
// two manifests with DIFFERENT display names but the SAME slug collide.
func TestRunDetectsDuplicateSlugs(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "manifest.json")
	writeManifest(t, filepath.Join(root, "vulnerabilities", "a"), validYAML)
	otherName := strings.Replace(validYAML, `"Nuclei Scanner"`, `"WPScan Scanner"`, 1)
	writeManifest(t, filepath.Join(root, "discovery", "b"), otherName)
	err := run(root, out)
	if err == nil {
		t.Fatal("expected duplicate-slug error")
	}
	if !strings.Contains(err.Error(), "duplicate connector slug") {
		t.Fatalf("expected error mentioning duplicate connector slug, got %q", err.Error())
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
