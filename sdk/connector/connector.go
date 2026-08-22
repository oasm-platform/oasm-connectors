package connector

import "context"

// Adapter is the tool-specific implementation that each connector provides.
type Adapter interface {
	Validate(ctx context.Context, inputs map[string]any) error
	Execute(ctx context.Context, inputs map[string]any, out chan<- []byte) error
}

// Connector wraps an Adapter and exposes Validate/Execute.
type Connector struct{ adapter Adapter }

// New creates a Connector from an Adapter.
func New(a Adapter) *Connector { return &Connector{adapter: a} }

// Validate delegates to the underlying Adapter.
func (c *Connector) Validate(ctx context.Context, inputs map[string]any) error {
	return c.adapter.Validate(ctx, inputs)
}

// Execute delegates to the underlying Adapter.
func (c *Connector) Execute(ctx context.Context, inputs map[string]any, out chan<- []byte) error {
	return c.adapter.Execute(ctx, inputs, out)
}
