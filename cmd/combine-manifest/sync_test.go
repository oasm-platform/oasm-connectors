package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestCheckedInManifestJSONCurrent guards the checked-in manifest.json
// against staleness: it regenerates the manifest from the
// vulnerabilities/*/manifest.yaml sources (same code path as the CLI, minus
// the process spawn) and compares the connectors payload with the committed
// copy. generatedAt is intentionally ignored — it changes on every run.
func TestCheckedInManifestJSONCurrent(t *testing.T) {
	root := os.Getenv("OASM_CONNECTORS_ROOT")
	if root == "" {
		root = filepath.Join("..", "..") // repo root, relative to this package dir
	}
	checkedIn := filepath.Join(root, "manifest.json")
	if _, err := os.Stat(checkedIn); err != nil {
		t.Fatalf("checked-in %s not found: %v", checkedIn, err)
	}

	tmp := filepath.Join(t.TempDir(), "manifest.json")
	if err := run(root, tmp); err != nil {
		t.Fatalf("regenerate manifest: %v", err)
	}

	want := readConnectors(t, checkedIn)
	got := readConnectors(t, tmp)
	// The stdlib PNG encoder emits different bytes per Go toolchain (1.26 vs
	// 1.27 differ on the same input), so comparing the base64 logo verbatim
	// reports drift on a manifest that is pixel-identical. Compare what the
	// console actually renders instead.
	for _, m := range append(append([]*Manifest{}, want...), got...) {
		normalizeLogo(t, m)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manifest.json stale: chạy combine-manifest và commit lại manifest.json (go run ./cmd/combine-manifest)\nchecked-in connectors: %v\nregenerated connectors: %v", want, got)
	}
}

// normalizeLogo replaces the embedded PNG with a digest of its decoded pixels.
func normalizeLogo(t *testing.T, m *Manifest) {
	t.Helper()
	if m.Logo == "" {
		return
	}
	raw, err := base64.StdEncoding.DecodeString(m.Logo)
	if err != nil {
		t.Fatalf("%s: logo is not base64: %v", m.Slug, err)
	}
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: logo is not a png: %v", m.Slug, err)
	}
	bounds := img.Bounds()
	rgba := image.NewRGBA(image.Rect(0, 0, bounds.Dx(), bounds.Dy()))
	draw.Draw(rgba, rgba.Bounds(), img, bounds.Min, draw.Src)
	m.Logo = fmt.Sprintf("png:%dx%d:%x", bounds.Dx(), bounds.Dy(), sha256.Sum256(rgba.Pix))
}

func readConnectors(t *testing.T, path string) []*Manifest {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Connectors []*Manifest `json:"connectors"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return doc.Connectors
}
