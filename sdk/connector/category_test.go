package connector

import (
	"context"
	"testing"
)

func TestCategoryRoundTrip(t *testing.T) {
	ctx := WithCategory(context.Background(), "vulnerabilities")
	if got := Category(ctx); got != "vulnerabilities" {
		t.Fatalf("Category = %q", got)
	}
}

// An old worker sends no category: the adapter must see "" and use its default.
func TestCategoryDefaultsToEmpty(t *testing.T) {
	if got := Category(context.Background()); got != "" {
		t.Fatalf("Category = %q, want empty", got)
	}
}
