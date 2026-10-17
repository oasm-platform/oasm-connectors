package connector

import "context"

type categoryKey struct{}

// WithCategory attaches the category the platform asked this execution to run.
func WithCategory(ctx context.Context, category string) context.Context {
	return context.WithValue(ctx, categoryKey{}, category)
}

// Category is the platform category this execution runs (e.g. "vulnerabilities").
// Empty means the connector's default — its first manifest capability — e.g.
// an older worker sent none.
func Category(ctx context.Context) string {
	c, _ := ctx.Value(categoryKey{}).(string)
	return c
}
