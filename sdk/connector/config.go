package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type configKey struct{}

// WithConfig attaches the per-job config profile (raw JSON) to ctx. The
// runtime calls it per execution so a warm-pool reused container sees its own
// job's config instead of its first-run OASM_CONFIG env.
func WithConfig(ctx context.Context, raw string) context.Context {
	return context.WithValue(ctx, configKey{}, raw)
}

// LoadConfig decodes the per-job config profile into T. Source order: the
// ctx value set by WithConfig, then the OASM_CONFIG env var (first-run
// container config). Blank yields a zero T; malformed JSON is an error.
func LoadConfig[T any](ctx context.Context) (*T, error) {
	raw, _ := ctx.Value(configKey{}).(string)
	if strings.TrimSpace(raw) == "" {
		raw = os.Getenv("OASM_CONFIG")
	}
	var cfg T
	if strings.TrimSpace(raw) == "" {
		return &cfg, nil
	}
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}
	return &cfg, nil
}

// HasConfig reports whether a non-blank config profile is available from ctx
// or OASM_CONFIG — for adapters that keep a legacy env fallback when no
// profile was shipped at all.
func HasConfig(ctx context.Context) bool {
	raw, _ := ctx.Value(configKey{}).(string)
	return strings.TrimSpace(raw) != "" || strings.TrimSpace(os.Getenv("OASM_CONFIG")) != ""
}
