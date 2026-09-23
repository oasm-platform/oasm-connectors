package main

import (
	"context"
	"fmt"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// OpenVASAdapter drives a Greenbone/OpenVAS gvmd instance over GMP.
// Execute is a stub until the scan flow lands in a later todo.
type OpenVASAdapter struct{}

// Validate is a no-op, matching the sibling connectors.
func (a *OpenVASAdapter) Validate(_ context.Context, _ map[string]any) error { return nil }

// Execute is not implemented yet.
func (a *OpenVASAdapter) Execute(_ context.Context, _ map[string]any, _ chan<- connector.Finding) error {
	return fmt.Errorf("openvas connector: not implemented")
}
