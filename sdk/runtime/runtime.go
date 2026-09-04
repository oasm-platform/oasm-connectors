package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/oasm-platform/oasm-connectors/sdk/env"
	"github.com/oasm-platform/oasm-connectors/sdk/logging"
	pb "github.com/oasm-platform/oasm-connectors/sdk/proto/gen"
	"github.com/oasm-platform/oasm-connectors/sdk/transport"
)

// Runtime owns a Connector and runs until the context is cancelled.
type Runtime struct {
	conn   *connector.Connector
	logger *logging.Logger

	// cancels holds the cancel func of every in-flight execution, keyed by
	// ExecutionId, so Run's loop can abort an execution on a protocol Cancel.
	// Written by handleExecute goroutines, read by the Run loop's Cancel
	// handler — hence the mutex.
	cancelsMu sync.Mutex
	cancels   map[string]context.CancelFunc
}

// New creates a Runtime for the given Connector.
func New(c *connector.Connector) *Runtime {
	return &Runtime{
		conn:    c,
		logger:  logging.New("runtime"),
		cancels: make(map[string]context.CancelFunc),
	}
}

// sendTimeout bounds a single stream send so a worker that stops reading
// cannot wedge the connector forever. Also bounds the wait for an adapter to
// stop after cancellation.
// ponytail: fixed 30s; make configurable when workers report tail latencies.
const sendTimeout = 30 * time.Second

// Run connects to the Worker gRPC server using env-injected config,
// registers, and enters the execute loop. Falls back to blocking on
// ctx.Done() when WORKER_GRPC_ADDR is not set (legacy mode).
func (r *Runtime) Run(ctx context.Context) error {
	cfg, err := env.Load()
	if err != nil {
		// No Worker config — legacy mode, just block
		r.logger.Info("no WORKER_GRPC_ADDR set, blocking on context")
		<-ctx.Done()
		return ctx.Err()
	}

	inputs := env.LoadInputs()
	r.logger.Infof("loaded %d env inputs", len(inputs))
	r.logger.Infof("worker config: addr=%s token_set=%t execution=%s job=%s tool=%s", cfg.WorkerAddr, cfg.Token != "", cfg.ExecutionID, cfg.JobID, cfg.Tool)

	// Dial Worker
	conn, err := transport.Connect(ctx, cfg.WorkerAddr)
	if err != nil {
		return fmt.Errorf("retryable: dial worker: %w", err)
	}
	defer conn.Close()

	client := pb.NewConnectorServiceClient(conn)
	stream, err := client.Connect(ctx)
	if err != nil {
		return fmt.Errorf("retryable: open connect stream: %w", err)
	}

	// Register — attach execution identity so the Worker can route
	// ExecuteJob back on this stream.
	register := &pb.Register{
		Token:       cfg.Token,
		ExecutionId: cfg.ExecutionID,
		JobId:       cfg.JobID,
		Tool:        cfg.Tool,
	}
	if err := stream.Send(&pb.ConnectorMessage{
		Message: &pb.ConnectorMessage_Register{
			Register: register,
		},
	}); err != nil {
		return fmt.Errorf("retryable: send register: %w", err)
	}

	// Wait for RegisterAck
	ackMsg, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("retryable: wait register ack: %w", err)
	}
	ack := ackMsg.GetRegisterAck()
	if ack == nil || !ack.Accepted {
		reason := "unknown"
		if ack != nil {
			reason = ack.Reason
		}
		r.logger.Errorf("registration rejected: %s", reason)
		return fmt.Errorf("fatal: registration rejected: %s", reason)
	}
	r.logger.Info("registered with worker")

	// Receive Worker messages in a dedicated goroutine so Cancel messages can
	// be processed while an execution streams results. A synchronous loop
	// would only see the Cancel after the execution finished — the stuck
	// stream the per-execution cancel map exists to fix. Recv runs in exactly
	// one goroutine (grpc forbids concurrent RecvMsg on a stream); sends from
	// handleExecute are safe alongside it.
	msgCh := make(chan *pb.WorkerMessage, 16)
	recvErrCh := make(chan error, 1)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				select {
				case recvErrCh <- err:
				case <-ctx.Done():
				}
				return
			}
			select {
			case msgCh <- msg:
			case <-ctx.Done():
				return
			}
		}
	}()

	// handleExecute goroutines report stream-fatal errors back to the loop.
	execErrCh := make(chan error, 8)

	for {
		select {
		case msg := <-msgCh:
			switch m := msg.Message.(type) {
			case *pb.WorkerMessage_Execute:
				// Execution runs concurrently with the recv loop so a later
				// Cancel can abort it via the cancel map. One stream carries
				// one execution (the worker maps a stream per execution), so
				// sends from different executions never interleave.
				go func() { execErrCh <- r.handleExecute(ctx, stream, m.Execute, inputs) }()

			case *pb.WorkerMessage_Cancel:
				r.logger.Infof("cancel execution_id=%s", m.Cancel.ExecutionId)
				r.cancelExecution(m.Cancel.ExecutionId)
			}

		case err := <-recvErrCh:
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if errors.Is(err, io.EOF) {
				r.logger.Infof("stream closed by worker: %v", err)
				return nil
			}
			r.logger.Errorf("recv failed: %v", err)
			return fmt.Errorf("retryable: recv: %w", err)

		case err := <-execErrCh:
			if err != nil {
				return err
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// cancelExecution aborts the in-flight execution identified by execID, if
// any. Unknown IDs are a no-op (e.g. late Cancels after completion).
func (r *Runtime) cancelExecution(execID string) {
	r.cancelsMu.Lock()
	cancel, ok := r.cancels[execID]
	r.cancelsMu.Unlock()
	if ok {
		cancel()
	}
}

// sendStreamMsg performs one bounded stream send. abortCtx drives the send:
// when it is cancelled (protocol Cancel for the execution, or Run shutdown)
// the send is abandoned. On timeout the send is abandoned too — the caller
// returns the error, the Run loop tears the stream down, and the abandoned
// Send goroutine unblocks and exits. Concurrent calls from multiple
// goroutines on the same stream are not supported.
func (r *Runtime) sendStreamMsg(abortCtx context.Context, stream pb.ConnectorService_ConnectClient, msg *pb.ConnectorMessage) error {
	sendCh := make(chan error, 1)
	go func() { sendCh <- stream.Send(msg) }()

	timer := time.NewTimer(sendTimeout)
	defer timer.Stop()

	select {
	case err := <-sendCh:
		return err
	case <-abortCtx.Done():
		return fmt.Errorf("send aborted: %w", abortCtx.Err())
	case <-timer.C:
		return fmt.Errorf("send result timeout after %s", sendTimeout)
	}
}

// handleExecute runs the adapter for a single ExecuteJob and streams
// results back. It runs in its own goroutine: the Run loop registers a
// per-execution cancel func in Runtime.cancels, so a protocol Cancel can
// abort this execution mid-stream (execCtx cancels, the adapter returns,
// out closes, and this function falls through to Done).
//
// Error convention on Done.Error (plain string, proto-compatible):
//   - "retryable: " prefix for transient failures — dial/recv/send-timeout,
//     adapter/scanner errors, cancellation.
//   - "fatal: " prefix for configuration/target errors.
//
// Adapter errors are embedded verbatim; the adapter is expected to apply the
// same prefix to its own errors. The SDK applies the prefix to the errors it
// generates itself.
func (r *Runtime) handleExecute(ctx context.Context, stream pb.ConnectorService_ConnectClient, exec *pb.ExecuteJob, envInputs map[string]any) error {
	r.logger.Infof("execute job_id=%s tool=%s exec_id=%s", exec.JobId, exec.Tool, exec.ExecutionId)

	// Per-execution cancel handle — stored so Run's Cancel handler can abort
	// this execution, removed when this execution finishes.
	execCtx, cancel := context.WithCancel(ctx)
	r.cancelsMu.Lock()
	r.cancels[exec.ExecutionId] = cancel
	r.cancelsMu.Unlock()
	defer func() {
		r.cancelsMu.Lock()
		delete(r.cancels, exec.ExecutionId)
		r.cancelsMu.Unlock()
	}()

	// Merge inputs: env defaults, Worker-provided override (worker wins).
	inputs := make(map[string]any, len(envInputs)+len(exec.Inputs))
	for k, v := range envInputs {
		inputs[k] = v
	}
	for k, v := range exec.Inputs {
		inputs[k] = v
	}

	// 128-buffer so a burst of findings does not stall the adapter while a
	// send to a slow worker is in flight.
	out := make(chan []byte, 128)
	errCh := make(chan error, 1)

	go func() {
		errCh <- r.conn.Execute(execCtx, inputs, out)
		close(out)
	}()

	// Stream results — sends are serialized inside this goroutine; each send
	// is bounded so a stalled worker cannot wedge the stream (a wedged send
	// would also make the worker's Cancel unprocessable).
	n := 0
	for data := range out {
		if err := r.sendStreamMsg(execCtx, stream, &pb.ConnectorMessage{
			Message: &pb.ConnectorMessage_Result{
				Result: &pb.Result{
					ExecutionId: exec.ExecutionId,
					Data:        data,
				},
			},
		}); err != nil {
			if execCtx.Err() != nil {
				// Cancelled: stop streaming; cancellation is reported in Done.
				r.logger.Infof("result send aborted: execution=%s err=%v", exec.ExecutionId, err)
				break
			}
			r.logger.Errorf("send failed: execution=%s err=%v", exec.ExecutionId, err)
			return fmt.Errorf("retryable: %w", err)
		}
		n++
	}

	// Wait for the adapter; bounded so an adapter that ignores cancellation
	// cannot hang the stream forever.
	var adapterErr error
	select {
	case adapterErr = <-errCh:
	case <-time.After(sendTimeout):
		adapterErr = fmt.Errorf("retryable: adapter did not stop within %s after cancellation", sendTimeout)
		r.logger.Errorf("adapter did not stop: execution=%s job=%s tool=%s", exec.ExecutionId, exec.JobId, exec.Tool)
	}

	// Send Done
	doneMsg := &pb.Done{ExecutionId: exec.ExecutionId}
	if adapterErr != nil {
		doneMsg.Error = adapterErr.Error()
		r.logger.Errorf("adapter error: execution=%s job=%s tool=%s err=%v", exec.ExecutionId, exec.JobId, exec.Tool, adapterErr)
	}
	// Done goes out on the parent context so it still succeeds after a
	// protocol cancel of this execution.
	if err := r.sendStreamMsg(ctx, stream, &pb.ConnectorMessage{
		Message: &pb.ConnectorMessage_Done{Done: doneMsg},
	}); err != nil {
		r.logger.Errorf("send failed: execution=%s err=%v", exec.ExecutionId, err)
		return fmt.Errorf("retryable: %w", err)
	}
	r.logger.Infof("execution done: execution=%s job=%s tool=%s results=%d", exec.ExecutionId, exec.JobId, exec.Tool, n)

	return nil
}
