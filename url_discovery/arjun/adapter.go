package main

import (
	"context"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// ArjunAdapter is a temporary stub so the module compiles; T9 replaces it.
type ArjunAdapter struct{}

func (a ArjunAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

func (a ArjunAdapter) Execute(_ context.Context, _ map[string]any, _ chan<- connector.Finding) error {
	return nil
}
