package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"
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
//
// The base logger is deliberately job-less: nothing is known about the job until
// env.Load in Run, which then swaps in a logger carrying execution_id/job_id/
// tool/image/trace_id so every later line is correlated. Run's own startup lines
// are therefore prefixed by hand.
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

// findingPreviewLimit caps how many finding summaries a failed job leaves in
// the container log. Enough to identify what the tool was producing, small
// enough that a 50k-finding scan does not bury the rest of the log.
const findingPreviewLimit = 20

// renderFinding renders one finding as a single log-safe line.
func renderFinding(f connector.Finding) string {
	where := f.MatchedAt
	if where == "" {
		where = f.Host
	}
	if where == "" {
		where = "-"
	}
	return fmt.Sprintf("%q sev=%s at=%s", f.Name, f.Severity, where)
}

// previewLines joins preview entries and marks truncation, so a preview never
// looks like the complete result set.
func previewLines(preview []string, total int) string {
	out := strings.Join(preview, " | ")
	if total > len(preview) {
		out += fmt.Sprintf(" | …+%d more", total-len(preview))
	}
	return out
}

// errOrNone keeps the outcome line readable when the run failed early, before
// any error string existed, rather than printing error=<nil>.
func errOrNone(err error) string {
	if err == nil {
		return "none"
	}
	return err.Error()
}

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
	// From here on every line is prefixed with the job identity: a warm-pool
	// container serves many jobs in one log stream, so execution_id/job_id are
	// what makes a failure traceable back to the job that caused it.
	r.logger = logging.New("runtime").
		WithFields("execution_id", cfg.ExecutionID, "job_id", cfg.JobID, "tool", cfg.Tool).
		WithTraceID(cfg.TraceID)
	r.logger.Infof("connector starting: pid=%d inputs=%s", os.Getpid(), logging.Summarize(inputs, 120))
	r.logger.Infof("worker config: addr=%s token_set=%t tls=%t", cfg.WorkerAddr, cfg.Token != "", os.Getenv("WORKER_TLS_CA") != "" && os.Getenv("WORKER_TLS_CERT") != "" && os.Getenv("WORKER_TLS_KEY") != "")

	// Dial Worker — mTLS when all three WORKER_TLS_* vars are set, plaintext
	// otherwise (missing any var keeps the historical plaintext behavior).
	// Empty serverName lets gRPC derive it from the dial address, so the
	// Worker cert must cover the address it is dialed at.
	caFile, certFile, keyFile, tlsEnabled := env.TLSFiles()
	var conn *grpc.ClientConn
	r.logger.Debugf("dialing worker addr=%s tls=%t", cfg.WorkerAddr, tlsEnabled)
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
	r.logger.Infof("registered with worker: addr=%s", cfg.WorkerAddr)

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
				r.logger.Debugf("recv loop ended: %v", err)
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
				if m.Execute == nil {
					continue
				}
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
					// The gate must be released on EVERY exit path: a stuck
					// gate would wedge every later execution on this stream.
					defer func() { <-execGate }()
					execErrCh <- r.handleExecute(ctx, stream, m.Execute, inputs)
				}()

			case *pb.WorkerMessage_Cancel:
				if m.Cancel == nil {
					continue
				}
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
	// execLog is the per-execution logger: it carries the ExecuteJob's OWN
	// identity, not the process-startup env. A warm-pool container logs several
	// jobs into one stream, and the ExecuteJob is the authoritative source for
	// which one a line belongs to.
	execLog := r.logger.WithFields("execution_id", exec.ExecutionId, "job_id", exec.JobId, "tool", exec.Tool, "image", exec.Image)
	start := time.Now()
	execLog.Infof("execute start: inputs=%s config=%s",
		logging.Summarize(exec.Inputs, 200), logging.Summarize(exec.Config, 200))

	// Per-execution cancel handle — stored so Run's Cancel handler can abort
	// this execution, removed when this execution finishes.
	execCtx, cancel := context.WithCancel(ctx)
	// Release the per-execution context on every exit path: without this, a
	// handleExecute that returns early (send failure, invalid finding) leaves
	// an adapter blocked on `out <- f` wedged until process exit.
	defer cancel()
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
	// The merged view is what the adapter actually sees; log it once so a
	// "wrong target" report always has the effective inputs next to it.
	execLog.Infof("effective inputs: %s", logging.Summarize(inputs, 200))

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
		execLog.Infof("config override applied: profile_bytes=%d config_keys=%s", len(raw), logging.Keys(exec.Config))
	}

	// 128-buffer so a burst of findings does not stall the adapter while a
	// send to a slow worker is in flight.
	out := make(chan connector.Finding, 128)
	errCh := make(chan error, 1)

	// The adapter runs in its own goroutine; a panic there would otherwise kill
	// the whole process (warm-pool container survives to serve the next job).
	// close(out) must still run so the streaming loop above terminates.
	go func() {
		defer close(out)
		defer func() {
			if p := recover(); p != nil {
				// The stack is the only way to find the panicking line once the
				// container is gone (warm pool keeps serving; upstream logs roll).
				stack := logging.Truncate(string(debug.Stack()), 2000)
				execLog.Errorf("adapter panic: %v\n%s", p, stack)
				errCh <- fmt.Errorf("retryable: adapter panic: %v", p)
			}
		}()
		execLog.Debugf("adapter starting")
		execErr := r.conn.Execute(execCtx, inputs, out)
		execLog.Debugf("adapter returned after %s: err=%v", time.Since(start).Round(time.Millisecond), execErr)
		errCh <- execErr
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
	var sendErr error
	var preview []string
	// firstFinding is logged at INFO even without LOG_LEVEL=debug: seeing WHICH
	// item was emitted is what separates "scanner found nothing" from "scanner
	// output failed to parse" when a job returns fewer results than expected.
	var firstFinding string
	for f := range out {
		if err := f.Validate(); err != nil {
			invalidErr = fmt.Errorf("fatal: finding %d invalid: %w", n, err)
			execLog.Errorf("invalid finding dropped: index=%d name=%q severity=%q err=%v", n, f.Name, f.Severity, err)
			cancel()
			break
		}
		if firstFinding == "" {
			firstFinding = renderFinding(f)
			execLog.Infof("first finding: %s", firstFinding)
		}
		if len(preview) < findingPreviewLimit {
			preview = append(preview, renderFinding(f))
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
				execLog.Infof("result send aborted after %d result(s): err=%v", n, err)
				break
			}
			// A failed send must still reach the worker as a Done error, not
			// as a silently torn-down stream: unblock the adapter, then fall
			// through to the Done path.
			execLog.Errorf("send failed after %d result(s): err=%v", n, err)
			sendErr = fmt.Errorf("retryable: %w", err)
			cancel()
			break
		}
		n++
		// Per-result tracing at debug level; the aggregate is logged on Done.
		execLog.Debugf("streamed result %d name=%q severity=%q", n, f.Name, f.Severity)
	}
	if len(preview) > 0 {
		execLog.Debugf("emitted preview: %s", previewLines(preview, n))
	}

	// Wait for the adapter; bounded so an adapter that ignores cancellation
	// cannot hang the stream forever. Always awaited: the next execution must
	// not start while this one is still running (the exec gate serializes
	// process-global state such as the restored OASM_CONFIG).
	var adapterErr error
	select {
	case adapterErr = <-errCh:
	case <-time.After(sendTimeout):
		adapterErr = fmt.Errorf("retryable: adapter did not stop within %s after cancellation", sendTimeout)
		execLog.Errorf("adapter did not stop within %s; abandoning execution", sendTimeout)
	}

	// An invalid finding outranks any adapter error: it is why the stream
	// stopped, and the worker must see it on the Done path. A send failure
	// outranks the cancellation error it caused.
	switch {
	case invalidErr != nil:
		adapterErr = invalidErr
	case sendErr != nil:
		adapterErr = sendErr
	}

	// Send Done
	doneMsg := &pb.Done{ExecutionId: exec.ExecutionId}
	if adapterErr != nil {
		doneMsg.Error = adapterErr.Error()
		execLog.Errorf("adapter error after %d result(s) in %s: %v", n, time.Since(start).Round(time.Millisecond), adapterErr)
	} else if execCtx.Err() != nil {
		// The execution was cancelled but the adapter swallowed the error
		// (returned nil): the worker must still learn the run did not finish.
		doneMsg.Error = context.Canceled.Error()
		execLog.Warnf("execution cancelled but adapter returned nil; reporting canceled: results=%d elapsed=%s", n, time.Since(start).Round(time.Millisecond))
	}
	// Done goes out on the parent context so it still succeeds after a
	// protocol cancel of this execution.
	if err := r.sendStreamMsg(ctx, stream, &pb.ConnectorMessage{
		Message: &pb.ConnectorMessage_Done{Done: doneMsg},
	}); err != nil {
		execLog.Errorf("done send failed: results=%d err=%v", n, err)
		return fmt.Errorf("retryable: %w", err)
	}
	// Outcome line: SUCCESS (green) for a clean run, WARN for a run that
	// finished carrying an error — the colour alone says which at a glance.
	if adapterErr == nil && execCtx.Err() == nil {
		execLog.Successf("execution done: results=%d elapsed=%s", n, time.Since(start).Round(time.Millisecond))
	} else {
		execLog.Warnf("execution done: results=%d elapsed=%s error=%v", n, time.Since(start).Round(time.Millisecond), errOrNone(adapterErr))
	}

	return nil
}

// toProtoFinding maps a connector.Finding onto its wire representation. A
// zero Timestamp is omitted rather than shipped as a bogus epoch value.
func toProtoFinding(f connector.Finding) *pb.Finding {
	out := &pb.Finding{
		Name:        f.Name,
		Severity:    f.Severity,
		Description: f.Description,
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

		Synopsis:   f.Synopsis,
		Ports:      f.Ports,
		Authors:    f.Authors,
		VprScore:   f.VPRScore,
		BidId:      f.BIDID,
		CeaId:      f.CEAID,
		Iava:       f.IAVAID,
		Confidence: f.Confidence,
	}
	if !f.Timestamp.IsZero() {
		out.Timestamp = timestamppb.New(f.Timestamp)
	}
	if !f.PublicationDate.IsZero() {
		out.PublicationDate = timestamppb.New(f.PublicationDate)
	}
	if !f.ModificationDate.IsZero() {
		out.ModificationDate = timestamppb.New(f.ModificationDate)
	}
	return out
}
