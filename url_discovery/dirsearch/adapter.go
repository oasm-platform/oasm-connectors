package main

import (
	"context"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// DirsearchAdapter is a temporary stub so the module compiles; T6 replaces it.
type DirsearchAdapter struct{}

func (a DirsearchAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

func (a DirsearchAdapter) Execute(_ context.Context, _ map[string]any, _ chan<- connector.Finding) error {
	return nil
}
