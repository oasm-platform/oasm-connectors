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
	"image"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/image/draw"
	"gopkg.in/yaml.v3"
)

// Manifest mirrors manifest.yaml. Unknown fields are rejected (parity with
// additionalProperties:false in the old TS schema).
type Manifest struct {
	Name string `yaml:"name"          json:"name"`
	// Slug is the system-wide unique identifier (lowercase, [a-z0-9-]).
	// Name is the human display name and may contain spaces/uppercase.
	Slug             string   `yaml:"slug"          json:"slug"`
	Version          string   `yaml:"version"       json:"version"`
	Image            string   `yaml:"image"         json:"image"`
	Author           string   `yaml:"author"        json:"author"`
	PricingTier      []string `yaml:"pricingTier"   json:"pricingTier"`
	Homepage         string   `yaml:"homepage,omitempty"     json:"homepage,omitempty"`
	RepositoryURL    string   `yaml:"repositoryUrl,omitempty" json:"repositoryUrl,omitempty"`
	SupportURL       string   `yaml:"supportUrl,omitempty"    json:"supportUrl,omitempty"`
	ShortDescription string   `yaml:"shortDescription" json:"shortDescription"`
	Description      string   `yaml:"description"      json:"description"`
	// Capabilities are the modes this connector runs in, in order: the first is
	// the default when a workflow step names no category. Each declares the
	// target types it may scan and, optionally, its own inputs schema.
	Capabilities []Capability `yaml:"capabilities"  json:"capabilities"`
	// AgentTool exposes this connector as a callable tool to the OASM AI agent.
	AgentTool        bool           `yaml:"agentTool,omitempty" json:"agentTool,omitempty"`
	ConfigSchema     map[string]any `yaml:"configSchema,omitempty"    json:"configSchema,omitempty"`
	ResourceDefaults map[string]any `yaml:"resourceDefaults,omitempty" json:"resourceDefaults,omitempty"`
	// Logo is the base64-encoded logo.png sitting next to manifest.yaml.
	// yaml:"-" keeps "logo:" in manifest.yaml an unknown-field error; the
	// image itself never lives in YAML.
	Logo string `yaml:"-" json:"logo,omitempty"`
}

// Capability is one mode a connector runs in. TargetTypes lists the platform
// target types whose assets this mode can scan (see allowedTargetTypes); the
// platform never dispatches an asset of any other target type to it.
type Capability struct {
	Name         string         `yaml:"name"                   json:"name"`
	TargetTypes  []string       `yaml:"targetTypes"            json:"targetTypes"`
	InputsSchema map[string]any `yaml:"inputsSchema,omitempty" json:"inputsSchema,omitempty"`
}

var capabilityKeys = map[string]bool{"name": true, "targetTypes": true, "inputsSchema": true}

// UnmarshalYAML enforces the same strictness as the top level: node.Decode
// does not inherit the decoder's KnownFields(true), so unknown keys and
// non-mapping entries are rejected here.
func (c *Capability) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: capability must be a mapping with name and targetTypes", n.Line)
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i].Value; !capabilityKeys[k] {
			return fmt.Errorf("line %d: capability: unknown field %q", n.Content[i].Line, k)
		}
	}
	type plain Capability
	return n.Decode((*plain)(c))
}

var (
	// allowedCapabilities maps each capability to the platform category it runs
	// as (mirrors core-api capabilityToCategory). An unknown capability used to
	// fall back silently to "vulnerabilities" on the platform side, so it is
	// rejected here instead.
	allowedCapabilities = map[string]string{
		"subdomains": "subdomains", "http_probe": "http_probe", "ports_scanner": "ports_scanner",
		"vulnerabilities": "vulnerabilities", "screenshot": "screenshot", "url_discovery": "url_discovery",
		// Repository scanners (GIT_ORG targets) report findings as vulnerabilities.
		"secrets": "vulnerabilities", "sca": "vulnerabilities", "sast": "vulnerabilities",
	}
	// allowedTargetTypes mirrors the platform's TargetType enum, lowercased
	// to match workflow trigger names (e.g. `domain.create`).
	allowedTargetTypes = map[string]bool{
		"domain": true, "ip": true, "cidr": true, "git_org": true,
	}
	nameRe   = regexp.MustCompile(`^[a-z0-9-]+$`)
	skipDirs = map[string]bool{
		"sdk": true, "scripts": true, "templates": true,
		".github": true, "node_modules": true,
	}
)

func validate(m *Manifest, path string) error {
	if strings.TrimSpace(m.Name) == "" {
		return fmt.Errorf("name required")
	}
	if m.Slug == "" {
		return fmt.Errorf("slug required")
	}
	if !nameRe.MatchString(m.Slug) {
		return fmt.Errorf("invalid slug %q (must match ^[a-z0-9-]+$)", m.Slug)
	}
	if m.Version == "" {
		return fmt.Errorf("version required")
	}
	if m.Image == "" {
		return fmt.Errorf("image required")
	}
	if m.ShortDescription == "" {
		return fmt.Errorf("shortDescription required")
	}
	if m.Description == "" {
		return fmt.Errorf("description required")
	}
	if len(m.Capabilities) == 0 {
		return fmt.Errorf("at least one capability required")
	}
	// The connector receives the platform category, so two capabilities that
	// run as the same category would be indistinguishable to it.
	capByCategory := make(map[string]string, len(m.Capabilities))
	for _, c := range m.Capabilities {
		if c.Name == "" {
			return fmt.Errorf("empty capability")
		}
		category, ok := allowedCapabilities[c.Name]
		if !ok {
			return fmt.Errorf("invalid capability %q (must be one of %s)", c.Name, sortedKeys(allowedCapabilities))
		}
		if prev, taken := capByCategory[category]; taken {
			if prev == c.Name {
				return fmt.Errorf("duplicate capability %q", c.Name)
			}
			return fmt.Errorf("capabilities %q and %q both run as category %q", prev, c.Name, category)
		}
		capByCategory[category] = c.Name
		if err := validateTargetTypes(c.TargetTypes); err != nil {
			return fmt.Errorf("capability %q: %w", c.Name, err)
		}
	}
	if m.Author == "" {
		return fmt.Errorf("author required")
	}
	if len(m.PricingTier) == 0 {
		return fmt.Errorf("pricingTier required")
	}
	normalized := make([]string, 0, len(m.PricingTier))
	for _, t := range m.PricingTier {
		tier := strings.ToLower(strings.TrimSpace(t))
		if tier != "free" && tier != "paid" {
			return fmt.Errorf("invalid pricingTier %q (must be free|paid)", t)
		}
		normalized = append(normalized, tier)
	}
	m.PricingTier = normalized
	for _, field := range []struct {
		key string
		val string
	}{
		{"homepage", m.Homepage},
		{"repositoryUrl", m.RepositoryURL},
		{"supportUrl", m.SupportURL},
	} {
		if field.val != "" && strings.TrimSpace(field.val) == "" {
			return fmt.Errorf("%s must be non-empty if set", field.key)
		}
	}
	return nil
}

func validateTargetTypes(types []string) error {
	if len(types) == 0 {
		return fmt.Errorf("at least one targetType required")
	}
	seen := make(map[string]bool, len(types))
	for _, tt := range types {
		if !allowedTargetTypes[tt] {
			return fmt.Errorf("invalid targetType %q (must be one of %s)", tt, sortedKeys(allowedTargetTypes))
		}
		if seen[tt] {
			return fmt.Errorf("duplicate targetType %q", tt)
		}
		seen[tt] = true
	}
	return nil
}

// sortedKeys renders an allow-list deterministically for error messages.
func sortedKeys[V any](set map[string]V) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, "|")
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
		logo, err := loadLogo(logoPath)
		if err != nil {
			return nil, err
		}
		m.Logo = base64.StdEncoding.EncodeToString(logo)
	}
	return &m, nil
}

// maxLogoSize caps a logo's long edge in manifest.json. Icons render at ~40px
// in the console; 128px stays crisp on HiDPI while keeping the multi-hundred-
// kilobyte source PNGs out of the generated manifest.
const maxLogoSize = 128

// loadLogo reads the logo and downscales it to maxLogoSize on its long edge
// when oversized, rewriting logo.png in place so the repo file and the embedded
// base64 can never disagree. Logos already within budget are returned verbatim —
// never upscale or re-encode what is already small enough.
func loadLogo(logoPath string) ([]byte, error) {
	raw, err := os.ReadFile(logoPath)
	if err != nil {
		return nil, err
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", logoPath, err)
	}
	bounds := src.Bounds()
	w, h := bounds.Dx(), bounds.Dy()
	if w <= maxLogoSize && h <= maxLogoSize {
		return raw, nil
	}
	if w >= h {
		h = max(h*maxLogoSize/w, 1)
		w = maxLogoSize
	} else {
		w = max(w*maxLogoSize/h, 1)
		h = maxLogoSize
	}
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	draw.CatmullRom.Scale(dst, dst.Bounds(), src, bounds, draw.Over, nil)
	var buf bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&buf, dst); err != nil {
		return nil, fmt.Errorf("%s: %w", logoPath, err)
	}
	// Overwrite the source so the next run is a no-op (a resized logo is within
	// budget) and reviewers see the actual shipped icon in the diff. ponytail:
	// the source is left untouched if this write fails, which surfaces as a
	// read-only-checkout build error instead of silently diverging.
	if err := os.WriteFile(logoPath, buf.Bytes(), 0o644); err != nil {
		return nil, fmt.Errorf("%s: %w", logoPath, err)
	}
	return buf.Bytes(), nil
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
		if prev, dup := seen[m.Slug]; dup {
			return fmt.Errorf("duplicate connector slug %q in %s and %s", m.Slug, prev, p)
		}
		seen[m.Slug] = p
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
