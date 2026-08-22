package runtime

import (
	"context"

	"github.com/open-asm/oasm-connectors/sdk/connector"
)

// Runtime owns a Connector and runs until the context is cancelled.
type Runtime struct{ conn *connector.Connector }

// New creates a Runtime for the given Connector.
func New(c *connector.Connector) *Runtime { return &Runtime{conn: c} }

// Run blocks until ctx is cancelled and returns ctx.Err().
// ponytail: ceiling is minimal skeleton; real impl will dial Worker gRPC bidi and multiplex commands/events
func (r *Runtime) Run(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}
