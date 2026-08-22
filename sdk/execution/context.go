package execution

import "context"

// Context is the per-execution SDK context handed to an Adapter.
// ponytail: ceiling is channel-backed streaming + context cancellation;
// richer JobID/Tool/Image/TraceID fields can be added when Worker proto lands.
type Context struct {
	ctx    context.Context
	cancel context.CancelFunc

	// ExecutionID is the unique execution identifier from Worker/Core.
	ExecutionID string
	// Inputs are the tool inputs for this execution (e.g. {"target": "https://example.com"}).
	Inputs map[string]any

	// JobID/Tool/Image/TraceID are optional enriched fields when available from JobSpec.
	JobID   string
	Tool    string
	Image   string
	TraceID string

	stream chan []byte
	// Out is an alias to stream for spec compatibility (sdk/execution/context.go spec).
	Out chan<- []byte
}

// NewContext creates an execution Context derived from parent.
// ExecutionID and inputs are preserved; cancellation propagates via Done()/Cancel().
func NewContext(parent context.Context, execID string, inputs map[string]any) *Context {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan []byte, 16)
	return &Context{
		ctx:         ctx,
		cancel:      cancel,
		ExecutionID: execID,
		Inputs:      inputs,
		stream:      ch,
		Out:         (chan<- []byte)(ch),
	}
}

// NewContextWithDetails is an extended constructor that also fills JobID/Tool/Image/TraceID
// and allows caller-supplied out channel. Kept for spec compatibility; delegates to NewContext.
func NewContextWithDetails(parent context.Context, jobID, tool, image string, inputs map[string]any, traceID string, out chan []byte) *Context {
	c := NewContext(parent, jobID, inputs)
	c.JobID = jobID
	c.Tool = tool
	c.Image = image
	c.TraceID = traceID
	if out != nil {
		c.Out = out
		// also replace internal stream so Emit/Stream stay consistent when out is used as sink
		c.stream = out
	}
	return c
}

// Done returns a channel that is closed when the execution is cancelled.
func (c *Context) Done() <-chan struct{} { return c.ctx.Done() }

// Cancel cancels the execution context.
func (c *Context) Cancel() { c.cancel() }

// Context returns the underlying context.Context.
func (c *Context) Context() context.Context { return c.ctx }

// Stream returns the read side of the output stream.
func (c *Context) Stream() <-chan []byte { return c.stream }

// Emit sends data to the stream without blocking; drops if buffer full or cancelled.
func (c *Context) Emit(b []byte) {
	select {
	case <-c.ctx.Done():
		return
	default:
	}
	select {
	case c.stream <- b:
	default:
	}
}

// EmitError is spec-compat alias that returns error instead of dropping silently.
func (c *Context) EmitError(data []byte) error {
	select {
	case <-c.ctx.Done():
		return c.ctx.Err()
	default:
	}
	select {
	case c.stream <- data:
		return nil
	default:
		return context.DeadlineExceeded
	}
}
