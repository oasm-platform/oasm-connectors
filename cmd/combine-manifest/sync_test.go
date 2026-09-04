package main

import (
	"encoding/json"
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
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("manifest.json stale: chạy combine-manifest và commit lại manifest.json (go run ./cmd/combine-manifest)\nchecked-in connectors: %v\nregenerated connectors: %v", want, got)
	}
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
