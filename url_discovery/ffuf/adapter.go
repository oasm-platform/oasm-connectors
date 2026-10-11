package main

import (
	"context"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// FfufAdapter is a temporary stub so the module compiles; T3 replaces it.
type FfufAdapter struct{}

func (a FfufAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

func (a FfufAdapter) Execute(_ context.Context, _ map[string]any, _ chan<- connector.Finding) error {
	return nil
}
