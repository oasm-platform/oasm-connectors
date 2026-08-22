// combine-manifest discovers connector manifests under <category>/<connector>/manifest.yaml,
// validates them, and writes the aggregated oasm-connectors/manifest.json.
// Replaces scripts/combine-manifest.ts — everything in this repo is Go.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Manifest mirrors manifest.yaml. Unknown fields are rejected (parity with
// additionalProperties:false in the old TS schema).
type Manifest struct {
	Name             string         `yaml:"name"          json:"name"`
	Version          string         `yaml:"version"       json:"version"`
	Image            string         `yaml:"image"         json:"image"`
	Capabilities     []string       `yaml:"capabilities"  json:"capabilities"`
	InputsSchema     map[string]any `yaml:"inputsSchema,omitempty"     json:"inputsSchema,omitempty"`
	ResourceDefaults map[string]any `yaml:"resourceDefaults,omitempty" json:"resourceDefaults,omitempty"`
	// Logo is the base64-encoded logo.png sitting next to manifest.yaml.
	// yaml:"-" keeps "logo:" in manifest.yaml an unknown-field error; the
	// image itself never lives in YAML.
	Logo string `yaml:"-" json:"logo,omitempty"`
}

var (
	nameRe   = regexp.MustCompile(`^[a-z0-9-]+$`)
	skipDirs = map[string]bool{
		"sdk": true, "scripts": true, "templates": true,
		".github": true, "node_modules": true, "cmd": true,
	}
)

func validate(m *Manifest, path string) error {
	if !nameRe.MatchString(m.Name) {
		return fmt.Errorf("invalid name %q (must match ^[a-z0-9-]+$)", m.Name)
	}
	if m.Version == "" {
		return fmt.Errorf("version required")
	}
	if m.Image == "" {
		return fmt.Errorf("image required")
	}
	if len(m.Capabilities) == 0 {
		return fmt.Errorf("at least one capability required")
	}
	for _, c := range m.Capabilities {
		if c == "" {
			return fmt.Errorf("empty capability")
		}
	}
	return nil
}

func discoverManifests(root string) ([]string, error) {
	var entries []string
	direct := filepath.Join(root, "manifest.yaml")
	if fileExists(direct) {
		return []string{direct}, nil
	}
	topEntries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	for _, top := range topEntries {
		if !top.IsDir() || skipDirs[top.Name()] || strings.HasPrefix(top.Name(), ".") {
			continue
		}
		topPath := filepath.Join(root, top.Name())
		if fileExists(filepath.Join(topPath, "manifest.yaml")) {
			entries = append(entries, filepath.Join(topPath, "manifest.yaml"))
			continue
		}
		subEntries, err := os.ReadDir(topPath)
		if err != nil {
			continue
		}
		for _, sub := range subEntries {
			if !sub.IsDir() {
				continue
			}
			p := filepath.Join(topPath, sub.Name(), "manifest.yaml")
			if fileExists(p) {
				entries = append(entries, p)
			}
		}
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no manifests found under %s (expected <category>/*/manifest.yaml)", root)
	}
	return entries, nil
}

func loadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // reject unknown fields (additionalProperties:false parity)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := validate(&m, path); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if logoPath := filepath.Join(filepath.Dir(path), "logo.png"); fileExists(logoPath) {
		logo, err := os.ReadFile(logoPath)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", logoPath, err)
		}
		m.Logo = base64.StdEncoding.EncodeToString(logo)
	}
	return &m, nil
}

type output struct {
	GeneratedAt string      `json:"generatedAt"`
	Connectors  []*Manifest `json:"connectors"`
}

func run(root, out string) error {
	entries, err := discoverManifests(root)
	if err != nil {
		return err
	}
	connectors := make([]*Manifest, 0, len(entries))
	seen := map[string]string{}
	for _, p := range entries {
		m, err := loadManifest(p)
		if err != nil {
			return err
		}
		if prev, dup := seen[m.Name]; dup {
			return fmt.Errorf("duplicate connector name %q in %s and %s", m.Name, prev, p)
		}
		seen[m.Name] = p
		connectors = append(connectors, m)
	}
	sort.Slice(connectors, func(i, j int) bool { return connectors[i].Name < connectors[j].Name })

	data, err := json.MarshalIndent(output{GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), Connectors: connectors}, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.WriteFile(out, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s with %d connectors\n", out, len(connectors))
	return nil
}

func main() {
	root := flag.String("root", "", "connectors repo root (default: auto-detect oasm-connectors)")
	out := flag.String("out", "", "output manifest.json path (default: <root>/manifest.json)")
	flag.Parse()

	rootPath := *root
	if rootPath == "" {
		rootPath = defaultRoot()
	}
	outPath := *out
	if outPath == "" {
		outPath = filepath.Join(rootPath, "manifest.json")
	}
	if err := run(rootPath, outPath); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// defaultRoot supports running from the platform repo root (parent of
// oasm-connectors), mirroring how scripts/combine-manifest.ts resolved paths.
func defaultRoot() string {
	wd, _ := os.Getwd()
	cand := filepath.Join(wd, "oasm-connectors")
	if info, err := os.Stat(cand); err == nil && info.IsDir() {
		return cand
	}
	return wd
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}
