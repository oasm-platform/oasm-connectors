package main

import (
	"context"
	"fmt"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// ponytail: scaffold stub — T4 replaces Execute with the target → scan → poll
// → collect → cleanup flow.
type AcunetixAdapter struct{}

var _ connector.Adapter = (*AcunetixAdapter)(nil)

func (a *AcunetixAdapter) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

func (a *AcunetixAdapter) Execute(_ context.Context, _ map[string]any, _ chan<- connector.Finding) error {
	return fmt.Errorf("acunetix connector: not implemented")
}
