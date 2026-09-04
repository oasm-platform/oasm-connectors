package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/oasm-platform/oasm-connectors/sdk/env"
	"github.com/oasm-platform/oasm-connectors/sdk/logging"
	pb "github.com/oasm-platform/oasm-connectors/sdk/proto/gen"
	"github.com/oasm-platform/oasm-connectors/sdk/transport"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
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
// registers, and enters the execute loop. Fails fast with a clear error when
// required config is missing (no point registering and waiting forever for an
// ExecuteJob the worker will never route): a connector only ever runs inside
// a worker-managed container, and the worker always injects WORKER_GRPC_ADDR,
// so a missing addr is a misconfiguration.
func (r *Runtime) Run(ctx context.Context) error {
	cfg, err := env.Load()
	if errors.Is(err, env.ErrWorkerAddrMissing) {
		// No Worker endpoint: a connector must be started by the Worker, which
		// always injects WORKER_GRPC_ADDR (open-asm worker buildContainerEnv).
		// Fail fast instead of blocking on ctx.Done() — with a Background
		// context that would deadlock (nil Done channel).
		r.logger.Errorf("fatal config: %v", err)
		return fmt.Errorf("fatal: %w: connector must be started by the worker; check WORKER_GRPC_ADDR", err)
	}
	if err != nil {
		// Missing execution identity (or other config problem): fail fast
		// instead of registering and hanging waiting for ExecuteJob.
		r.logger.Errorf("fatal config: %v", err)
		return fmt.Errorf("fatal: %w", err)
	}

	inputs := env.LoadInputs()
	r.logger.Infof("loaded %d env inputs", len(inputs))
	r.logger.Infof("worker config: addr=%s token_set=%t execution=%s job=%s tool=%s", cfg.WorkerAddr, cfg.Token != "", cfg.ExecutionID, cfg.JobID, cfg.Tool)

	// Dial Worker — mTLS when all three WORKER_TLS_* vars are set, plaintext
	// otherwise (missing any var keeps the historical plaintext behavior).
	// Empty serverName lets gRPC derive it from the dial address, so the
	// Worker cert must cover the address it is dialed at.
	caFile, certFile, keyFile, tlsEnabled := env.TLSFiles()
	var conn *grpc.ClientConn
	if tlsEnabled {
		r.logger.Info("worker mTLS enabled: WORKER_TLS_CA/CERT/KEY all set")
		creds, err := transport.LoadMTLS(caFile, certFile, keyFile, "")
		if err != nil {
			// Bad CA/cert/key material is operator config, not transient.
			return fmt.Errorf("fatal: load mTLS credentials: %w", err)
		}
		conn, err = transport.DialWithTLSCreds(cfg.WorkerAddr, creds)
		if err != nil {
			return fmt.Errorf("retryable: dial worker (mTLS): %w", err)
		}
	} else {
		conn, err = transport.Connect(ctx, cfg.WorkerAddr)
		if err != nil {
			return fmt.Errorf("retryable: dial worker: %w", err)
		}
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

	// One execution at a time per stream (worker MaxJobsPerContainer=1). The
	// gate serializes ExecuteJobs so a second execution never starts before
	// the first's Done was sent; the worker only sends the next Execute after
	// receiving Done, but the gate is the SDK-side enforcement.
	execGate := make(chan struct{}, 1)

	for {
		select {
		case msg := <-msgCh:
			switch m := msg.Message.(type) {
			case *pb.WorkerMessage_Execute:
				// Execution runs concurrently with the recv loop so a later
				// Cancel can abort it via the cancel map. A single stream
				// serves executions SEQUENTIALLY (warm-pool reuse, Phase 2);
				// a second ExecuteJob blocks on the gate until the first
				// finishes (Done sent).
				select {
				case execGate <- struct{}{}:
				case <-ctx.Done():
					return ctx.Err()
				}
				go func() {
					err := r.handleExecute(ctx, stream, m.Execute, inputs)
					<-execGate
					execErrCh <- err
				}()

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

	// Per-job config override (Phase 2 warm pool): a REUSED container keeps its
	// first-run OASM_CONFIG env; the worker ships the job's config profile as
	// JSON in ExecuteJob.config["oasm_config"]. Adapters read OASM_CONFIG via
	// os.Getenv at Execute time, so restore the env var around the adapter
	// run. The execGate guarantees a single in-flight execution, making this
	// process-global mutation race-free.
	if raw := exec.Config["oasm_config"]; raw != "" {
		prev := os.Getenv("OASM_CONFIG")
		os.Setenv("OASM_CONFIG", raw)
		defer os.Setenv("OASM_CONFIG", prev)
		r.logger.Infof("config override applied: execution=%s job=%s", exec.ExecutionId, exec.JobId)
	}

	// 128-buffer so a burst of findings does not stall the adapter while a
	// send to a slow worker is in flight.
	out := make(chan connector.Finding, 128)
	errCh := make(chan error, 1)

	go func() {
		errCh <- r.conn.Execute(execCtx, inputs, out)
		close(out)
	}()

	// Stream results — sends are serialized inside this goroutine; each send
	// is bounded so a stalled worker cannot wedge the stream (a wedged send
	// would also make the worker's Cancel unprocessable).
	//
	// Every finding is validated before it is transported. An invalid finding
	// is a protocol violation, not noise: the stream stops (fail fast), the
	// execution is cancelled so the adapter unblocks, and a fatal error
	// naming the index is carried to the worker by the Done message. No
	// silent drops — findings either ship or fail loudly.
	n := 0
	var invalidErr error
	for f := range out {
		if err := f.Validate(); err != nil {
			invalidErr = fmt.Errorf("fatal: finding %d invalid: %w", n, err)
			r.logger.Errorf("invalid finding dropped: execution=%s index=%d err=%v", exec.ExecutionId, n, err)
			cancel()
			break
		}
		if err := r.sendStreamMsg(execCtx, stream, &pb.ConnectorMessage{
			Message: &pb.ConnectorMessage_Result{
				Result: &pb.Result{
					ExecutionId: exec.ExecutionId,
					Findings:    []*pb.Finding{toProtoFinding(f)},
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

	// An invalid finding outranks any adapter error: it is why the stream
	// stopped, and the worker must see it on the Done path.
	if invalidErr != nil {
		adapterErr = invalidErr
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

// toProtoFinding maps a connector.Finding onto its wire representation. A
// zero Timestamp is omitted rather than shipped as a bogus epoch value.
func toProtoFinding(f connector.Finding) *pb.Finding {
	out := &pb.Finding{
		Name:        f.Name,
		Severity:    f.Severity,
		Tags:        f.Tags,
		References:  f.References,
		CveId:       f.CVEID,
		CweId:       f.CWEID,
		CvssScore:   f.CVSSScore,
		CvssMetrics: f.CVSSMetrics,
		EpssScore:   f.EPSSScore,
		Solution:    f.Solution,
		MatchedAt:   f.MatchedAt,
		Host:        f.Host,
		Ip:          f.IP,
	}
	if !f.Timestamp.IsZero() {
		out.Timestamp = timestamppb.New(f.Timestamp)
	}
	return out
}
