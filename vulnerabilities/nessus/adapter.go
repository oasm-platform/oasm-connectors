package main

import (
	"context"
	"fmt"
)

type NessusAdapter struct{}

func (a *NessusAdapter) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

func (a *NessusAdapter) Execute(_ context.Context, _ map[string]any, _ chan<- []byte) error {
	return fmt.Errorf("nessus connector: not implemented")
}
