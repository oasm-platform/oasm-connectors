//go:build !unix

package main

import (
	"context"
	"time"
)

// flockFile is a no-op off unix: the connector only ships in Linux images,
// this keeps local builds and tests compiling elsewhere.
func flockFile(ctx context.Context, _ string, _ bool, _ time.Duration) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return func() {}, nil
}
