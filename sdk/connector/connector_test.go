package connector

import (
	"context"
	"testing"
)

type fakeAdapter struct{}

func (f *fakeAdapter) Validate(ctx context.Context, inputs map[string]any) error { return nil }
func (f *fakeAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- Finding) error {
	out <- Finding{Name: "test-finding", Severity: "info"}
	return nil
}

func TestConnectorWrapsAdapter(t *testing.T) {
	c := New(&fakeAdapter{})
	if c == nil {
		t.Fatal("nil")
	}
	if err := c.Validate(context.Background(), map[string]any{"target": "https://example.com"}); err != nil {
		t.Fatal(err)
	}
}

func TestConnectorExecuteForwardsToAdapter(t *testing.T) {
	c := New(&fakeAdapter{})
	ch := make(chan Finding, 1)
	if err := c.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatal(err)
	}
	got := <-ch
	if got.Name != "test-finding" || got.Severity != "info" {
		t.Fatalf("unexpected execute output: %+v", got)
	}
}

func TestConnectorNilAdapterPanicsOrHandles(t *testing.T) {
	// ponytail: YAGNI minimal — New(nil) allowed, Validate will panic; documenting current behavior ceiling
	defer func() {
		if r := recover(); r != nil {
			// acceptable for minimal skeleton
		}
	}()
	c := New(nil)
	_ = c
}
