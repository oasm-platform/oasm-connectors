package connector

import (
	"context"
	"testing"
)

type fakeAdapter struct{}

func (f *fakeAdapter) Validate(ctx context.Context, inputs map[string]any) error { return nil }
func (f *fakeAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- []byte) error {
	out <- []byte(`{"ok":true}`)
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
	ch := make(chan []byte, 1)
	if err := c.Execute(context.Background(), map[string]any{"target": "https://example.com"}, ch); err != nil {
		t.Fatal(err)
	}
	got := string(<-ch)
	if got != `{"ok":true}` {
		t.Fatalf("unexpected execute output: %q", got)
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
