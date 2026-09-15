package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
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
image: ghcr.io/oasm-platform/connector-nuclei:3.3.0
author: "oasm"
pricingTier: [free]
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
		Author: "oasm", PricingTier: []string{"free"}}
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
	m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x", PricingTier: []string{"free"},
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

func TestValidateRejectsMissingPricingTier(t *testing.T) {
	for _, tiers := range [][]string{nil, {}} {
		m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x", Author: "oasm",
			PricingTier:      tiers,
			ShortDescription: "short", Description: "long description",
			Capabilities: []string{"vulnerabilities"}}
		err := validate(m, "test")
		if err == nil {
			t.Fatalf("expected error for missing/empty pricingTier (%v)", tiers)
		}
		if !strings.Contains(err.Error(), "pricingTier required") {
			t.Fatalf("expected error mentioning pricingTier required, got %q", err.Error())
		}
	}
}

func TestValidateRejectsInvalidPricingTier(t *testing.T) {
	for _, bad := range []string{"enterprise", "mit", "proprietary", "freemium"} {
		m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x", Author: "oasm",
			PricingTier:      []string{bad},
			ShortDescription: "short", Description: "long description",
			Capabilities: []string{"vulnerabilities"}}
		err := validate(m, "test")
		if err == nil {
			t.Fatalf("expected error for invalid pricingTier %q", bad)
		}
		if !strings.Contains(err.Error(), "pricingTier") {
			t.Fatalf("pricingTier %q: expected error mentioning pricingTier, got %q", bad, err.Error())
		}
	}
}

func TestValidateAcceptsPricingTierCaseInsensitiveTrim(t *testing.T) {
	for _, ok := range []string{"free", "paid", " Free ", "PAID"} {
		m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x", Author: "oasm",
			PricingTier:      []string{ok},
			ShortDescription: "short", Description: "long description",
			Capabilities: []string{"vulnerabilities"}}
		if err := validate(m, "test"); err != nil {
			t.Fatalf("pricingTier %q should be valid, got %v", ok, err)
		}
	}
}

func TestValidateAcceptsBothTiers(t *testing.T) {
	m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x", Author: "oasm",
		PricingTier:      []string{"free", "paid"},
		ShortDescription: "short", Description: "long description",
		Capabilities: []string{"vulnerabilities"}}
	if err := validate(m, "test"); err != nil {
		t.Fatalf("pricingTier [free paid] should be valid, got %v", err)
	}
	if len(m.PricingTier) != 2 || m.PricingTier[0] != "free" || m.PricingTier[1] != "paid" {
		t.Fatalf("PricingTier not normalized: %v", m.PricingTier)
	}
}

func TestValidateRejectsBlankOptionalURLs(t *testing.T) {
	for _, field := range []string{"homepage", "repositoryUrl", "supportUrl"} {
		m := &Manifest{Name: "nuclei", Slug: "nuclei", Version: "3.3.0", Image: "x", Author: "oasm",
			PricingTier:      []string{"free"},
			ShortDescription: "short", Description: "long description",
			Capabilities: []string{"vulnerabilities"}}
		switch field {
		case "homepage":
			m.Homepage = "   "
		case "repositoryUrl":
			m.RepositoryURL = "   "
		case "supportUrl":
			m.SupportURL = "   "
		}
		err := validate(m, "test")
		if err == nil {
			t.Fatalf("expected error for blank %s", field)
		}
		if !strings.Contains(err.Error(), field) {
			t.Fatalf("expected error mentioning %s, got %q", field, err.Error())
		}
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
	if len(m.PricingTier) != 1 || m.PricingTier[0] != "free" {
		t.Fatalf("PricingTier not parsed: %v", m.PricingTier)
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
	for _, key := range []string{"description", "shortDescription", "author", "slug"} {
		v, ok := doc.Connectors[0][key].(string)
		if !ok || v == "" {
			t.Fatalf("connector object missing non-empty %q key: %v", key, doc.Connectors[0])
		}
	}
	tiers, ok := doc.Connectors[0]["pricingTier"].([]any)
	if !ok || len(tiers) != 1 || tiers[0] != "free" {
		t.Fatalf("connector object pricingTier must be [free], got: %v", doc.Connectors[0])
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	root := t.TempDir()
	p := writeManifest(t, filepath.Join(root, "vulnerabilities", "nuclei"), validYAML+"unknownField: 1\n")
	if _, err := loadManifest(p); err == nil {
		t.Fatal("expected unknown-field rejection")
	}
}

func TestLoadRejectsScalarPricingTier(t *testing.T) {
	root := t.TempDir()
	scalar := strings.Replace(validYAML, "pricingTier: [free]", "pricingTier: free", 1)
	p := writeManifest(t, filepath.Join(root, "vulnerabilities", "nuclei"), scalar)
	if _, err := loadManifest(p); err == nil {
		t.Fatal("expected scalar pricingTier to be rejected (must be array)")
	}
}

func TestLoadRejectsLegacyLicenseField(t *testing.T) {
	root := t.TempDir()
	legacy := strings.Replace(validYAML, "pricingTier: [free]", "license: free", 1)
	p := writeManifest(t, filepath.Join(root, "vulnerabilities", "nuclei"), legacy)
	if _, err := loadManifest(p); err == nil {
		t.Fatal("expected legacy license field to be rejected as unknown field")
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

// makePNG encodes a w×h opaque RGBA test image as a real, decodable PNG.
func makePNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x % 256), G: uint8(y % 256), B: 200, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// embedLogo runs the full pipeline for a single connector whose logo.png holds
// the given raw bytes, and returns the decoded bytes of the emitted base64
// "logo" field.
func embedLogo(t *testing.T, raw []byte) []byte {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "vulnerabilities", "nuclei")
	writeManifest(t, dir, validYAML)
	if err := os.WriteFile(filepath.Join(dir, "logo.png"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(root, "manifest.json")
	if err := run(root, out); err != nil {
		t.Fatal(err)
	}
	doc, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Connectors []map[string]any `json:"connectors"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Connectors) != 1 {
		t.Fatalf("expected 1 connector, got %d", len(parsed.Connectors))
	}
	encoded, ok := parsed.Connectors[0]["logo"].(string)
	if !ok {
		t.Fatalf("connector object has no string \"logo\" key: %v", parsed.Connectors[0])
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("logo is not valid base64: %v", err)
	}
	return decoded
}

// TestRunEmbedsLogoBase64 proves the end-to-end embed path for a logo that is
// already within the 128px budget: it is passed through byte-for-byte, so the
// emitted base64 equals base64(logo.png).
func TestRunEmbedsLogoBase64(t *testing.T) {
	pngBytes := makePNG(t, 24, 24)
	got := base64.StdEncoding.EncodeToString(embedLogo(t, pngBytes))
	want := base64.StdEncoding.EncodeToString(pngBytes)
	if got != want {
		t.Fatalf("logo mismatch:\n got  %q\n want %q", got, want)
	}
}

// TestRunDownscalesOversizedLogoTo128 is the core behaviour: a 400×400 logo is
// resized to 128×128 before base64 encoding, so manifest.json stops carrying
// multi-hundred-kilobyte icons.
func TestRunDownscalesOversizedLogoTo128(t *testing.T) {
	raw := makePNG(t, 400, 400)
	decoded := embedLogo(t, raw)
	img, format, err := image.Decode(bytes.NewReader(decoded))
	if err != nil {
		t.Fatalf("emitted logo is not a decodable image: %v", err)
	}
	if format != "png" {
		t.Fatalf("expected png output, got %q", format)
	}
	if got := img.Bounds().Size(); got.X != 128 || got.Y != 128 {
		t.Fatalf("expected 128x128 logo, got %dx%d", got.X, got.Y)
	}
	if len(decoded) >= len(raw) {
		t.Fatalf("resize did not shrink the payload: %d bytes (from %d)", len(decoded), len(raw))
	}
}

// TestRunPreservesLogoAspectRatio covers the boundary where the logo is not
// square: the long edge is capped at 128 and the short edge scales with it.
func TestRunPreservesLogoAspectRatio(t *testing.T) {
	for _, tc := range []struct{ w, h, wantW, wantH int }{
		{400, 200, 128, 64},
		{200, 400, 64, 128},
		{129, 129, 128, 128},
	} {
		decoded := embedLogo(t, makePNG(t, tc.w, tc.h))
		img, _, err := image.Decode(bytes.NewReader(decoded))
		if err != nil {
			t.Fatalf("%dx%d: emitted logo is not a decodable image: %v", tc.w, tc.h, err)
		}
		got := img.Bounds().Size()
		if got.X != tc.wantW || got.Y != tc.wantH {
			t.Fatalf("%dx%d: expected %dx%d, got %dx%d", tc.w, tc.h, tc.wantW, tc.wantH, got.X, got.Y)
		}
	}
}

// TestRunKeepsSmallLogoUntouched guards the "never enlarge" boundary: a logo
// already within 128px must not be re-encoded (no upscaling, no quality loss).
func TestRunKeepsSmallLogoUntouched(t *testing.T) {
	raw := makePNG(t, 128, 128)
	if got := embedLogo(t, raw); !bytes.Equal(got, raw) {
		t.Fatalf("128x128 logo should be embedded verbatim, got %d bytes vs %d", len(got), len(raw))
	}
}

// TestLoadRejectsNonImageLogo pins the trust boundary: logo.png that is not a
// decodable image must fail the build loudly instead of shipping garbage.
func TestLoadRejectsNonImageLogo(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "vulnerabilities", "nuclei")
	writeManifest(t, dir, validYAML)
	if err := os.WriteFile(filepath.Join(dir, "logo.png"), []byte("not-an-image"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadManifest(filepath.Join(dir, "manifest.yaml"))
	if err == nil {
		t.Fatal("expected error for undecodable logo.png")
	}
	if !strings.Contains(err.Error(), "logo.png") {
		t.Fatalf("expected error mentioning logo.png, got %q", err.Error())
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
