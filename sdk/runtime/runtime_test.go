package runtime

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	pb "github.com/oasm-platform/oasm-connectors/sdk/proto/gen"
	"google.golang.org/grpc"
)

// fakeAdapter emits one finding and succeeds; mirrors adapter shape used by connectors.
type fakeAdapter struct {
	chunk *connector.Finding
	err   error
}

func (a *fakeAdapter) Validate(ctx context.Context, inputs map[string]any) error { return nil }
func (a *fakeAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	if a.chunk != nil {
		select {
		case out <- *a.chunk:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return a.err
}

// fakeConnectorServer is an in-process gRPC connector server: captures the
// Register message, acks it, then drives one ExecuteJob and collects Result/Done.
type fakeConnectorServer struct {
	pb.UnimplementedConnectorServiceServer
	registerCh chan *pb.Register
	execReq    *pb.ExecuteJob
	resultCh   chan *pb.Result
	doneCh     chan *pb.Done
}

func newFakeConnectorServer(exec *pb.ExecuteJob) *fakeConnectorServer {
	return &fakeConnectorServer{
		registerCh: make(chan *pb.Register, 1),
		execReq:    exec,
		resultCh:   make(chan *pb.Result, 16),
		doneCh:     make(chan *pb.Done, 1),
	}
}

func (s *fakeConnectorServer) Connect(stream pb.ConnectorService_ConnectServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	s.registerCh <- msg.GetRegister()

	ack := &pb.WorkerMessage{Message: &pb.WorkerMessage_RegisterAck{RegisterAck: &pb.RegisterAck{Accepted: true}}}
	if err := stream.Send(ack); err != nil {
		return err
	}
	if s.execReq != nil {
		if err := stream.Send(&pb.WorkerMessage{Message: &pb.WorkerMessage_Execute{Execute: s.execReq}}); err != nil {
			return err
		}
	}

	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch m := msg.Message.(type) {
		case *pb.ConnectorMessage_Result:
			s.resultCh <- m.Result
		case *pb.ConnectorMessage_Done:
			s.doneCh <- m.Done
			return nil
		}
	}
}

// rejectedConnectorServer acks Register with a rejection reason and keeps the
// stream open; the client is expected to hang up after seeing the rejection.
type rejectedConnectorServer struct {
	pb.UnimplementedConnectorServiceServer
	registerCh chan *pb.Register
	reason     string
}

func (s *rejectedConnectorServer) Connect(stream pb.ConnectorService_ConnectServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	s.registerCh <- msg.GetRegister()

	ack := &pb.WorkerMessage{Message: &pb.WorkerMessage_RegisterAck{RegisterAck: &pb.RegisterAck{Accepted: false, Reason: s.reason}}}
	if err := stream.Send(ack); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

// startFakeServer listens on an ephemeral localhost TCP port (transport.Connect
// has no dialer hook, so a real listener is the test seam) and returns the
// listener address.
func startFakeServer(t *testing.T, srv pb.ConnectorServiceServer) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })
	gs := grpc.NewServer()
	pb.RegisterConnectorServiceServer(gs, srv)
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

func runRuntime(t *testing.T, rt *Runtime) (context.CancelFunc, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- rt.Run(ctx) }()
	t.Cleanup(cancel)
	return cancel, errCh
}

func waitRegister(t *testing.T, srv *fakeConnectorServer) *pb.Register {
	t.Helper()
	return waitRegisterCh(t, srv.registerCh)
}

func waitRegisterCh(t *testing.T, ch <-chan *pb.Register) *pb.Register {
	t.Helper()
	select {
	case reg := <-ch:
		return reg
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Register")
		return nil
	}
}

func TestRunRegistersExecutionIdentity(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("WORKER_TOKEN", "tok-1")
	t.Setenv("EXECUTION_ID", "exec-1")
	t.Setenv("JOB_ID", "job-1")
	t.Setenv("TOOL", "nuclei")

	srv := newFakeConnectorServer(&pb.ExecuteJob{
		ExecutionId: "exec-1",
		JobId:       "job-1",
		Tool:        "nuclei",
		Inputs:      map[string]string{"target": "https://example.com"},
	})
	addr := startFakeServer(t, srv)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	adapter := &fakeAdapter{chunk: &connector.Finding{Name: "example-finding", Severity: "info", MatchedAt: "https://example.com"}}
	rt := New(connector.New(adapter))
	_, _ = runRuntime(t, rt)

	reg := waitRegister(t, srv)
	if reg.Token != "tok-1" {
		t.Errorf("Register.Token = %q, want tok-1", reg.Token)
	}
	if reg.ExecutionId != "exec-1" {
		t.Errorf("Register.ExecutionId = %q, want exec-1", reg.ExecutionId)
	}
	if reg.JobId != "job-1" {
		t.Errorf("Register.JobId = %q, want job-1", reg.JobId)
	}
	if reg.Tool != "nuclei" {
		t.Errorf("Register.Tool = %q, want nuclei", reg.Tool)
	}

	select {
	case res := <-srv.resultCh:
		if len(res.Findings) != 1 {
			t.Fatalf("Result.Findings length = %d, want 1", len(res.Findings))
		}
		if res.Findings[0].Name != "example-finding" {
			t.Errorf("Result.Findings[0].Name = %q, want %q", res.Findings[0].Name, "example-finding")
		}
		if res.Findings[0].Severity != "info" {
			t.Errorf("Result.Findings[0].Severity = %q, want %q", res.Findings[0].Severity, "info")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Result")
	}

	select {
	case done := <-srv.doneCh:
		if done.ExecutionId != "exec-1" {
			t.Errorf("Done.ExecutionId = %q, want exec-1", done.ExecutionId)
		}
		if done.Error != "" {
			t.Errorf("Done.Error = %q, want empty", done.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Done")
	}
}

func TestRunRejectedRegistrationReturnsReason(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("WORKER_TOKEN", "tok-reject")
	t.Setenv("EXECUTION_ID", "exec-reject")

	srv := &rejectedConnectorServer{
		registerCh: make(chan *pb.Register, 1),
		reason:     "bad token",
	}
	addr := startFakeServer(t, srv)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	rt := New(connector.New(&fakeAdapter{}))
	_, errCh := runRuntime(t, rt)

	select {
	case reg := <-srv.registerCh:
		if reg.Token != "tok-reject" {
			t.Errorf("Register.Token = %q, want tok-reject", reg.Token)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Register")
	}

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("Run returned nil, want registration rejection error")
		}
		if !strings.Contains(err.Error(), "bad token") {
			t.Errorf("Run error = %q, want it to contain %q", err.Error(), "bad token")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Run to return")
	}
}

func TestRunLegacyRegisterOmitsIdentity(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("WORKER_TOKEN", "tok-legacy")
	// EXECUTION_ID, JOB_ID, TOOL unset — legacy mode must stay intact; the
	// opt-out keeps the legacy no-identity path legal.
	t.Setenv("OASM_ALLOW_LEGACY_NO_EXEC_ID", "1")

	srv := newFakeConnectorServer(nil) // no Execute; register-only
	addr := startFakeServer(t, srv)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	rt := New(connector.New(&fakeAdapter{}))
	_, _ = runRuntime(t, rt)

	reg := waitRegister(t, srv)
	if reg.Token != "tok-legacy" {
		t.Errorf("Register.Token = %q, want tok-legacy", reg.Token)
	}
	if reg.ExecutionId != "" {
		t.Errorf("Register.ExecutionId = %q, want empty in legacy mode", reg.ExecutionId)
	}
	if reg.JobId != "" {
		t.Errorf("Register.JobId = %q, want empty in legacy mode", reg.JobId)
	}
	if reg.Tool != "" {
		t.Errorf("Register.Tool = %q, want empty in legacy mode", reg.Tool)
	}
}

// recordingAdapter captures the merged inputs handed to Execute.
type recordingAdapter struct {
	chunk    *connector.Finding
	err      error
	inputsCh chan map[string]any
}

func (a *recordingAdapter) Validate(ctx context.Context, inputs map[string]any) error { return nil }
func (a *recordingAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	if a.inputsCh != nil {
		a.inputsCh <- inputs
	}
	if a.chunk != nil {
		select {
		case out <- *a.chunk:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return a.err
}

// blockingAdapter starts an execution and blocks until its context is
// cancelled, recording that it was cancelled.
type blockingAdapter struct {
	startedCh chan struct{}
	gotCancel chan error
}

func (a *blockingAdapter) Validate(ctx context.Context, inputs map[string]any) error { return nil }
func (a *blockingAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	close(a.startedCh)
	<-ctx.Done()
	err := ctx.Err()
	a.gotCancel <- err
	return fmt.Errorf("cancelled by worker: %w", err)
}

// cancelServer drives one ExecuteJob and, when sendCancel is closed, emits a
// protocol Cancel message for it, then collects the resulting Done.
type cancelServer struct {
	pb.UnimplementedConnectorServiceServer
	execReq    *pb.ExecuteJob
	registerCh chan *pb.Register
	doneCh     chan *pb.Done
	sendCancel <-chan struct{} // closed by the test to trigger a Cancel message
	cancelSent chan struct{}   // closed once the Cancel message was written
}

func newCancelServer(exec *pb.ExecuteJob, sendCancel <-chan struct{}) *cancelServer {
	return &cancelServer{
		execReq:    exec,
		registerCh: make(chan *pb.Register, 1),
		doneCh:     make(chan *pb.Done, 1),
		sendCancel: sendCancel,
		cancelSent: make(chan struct{}),
	}
}

func (s *cancelServer) Connect(stream pb.ConnectorService_ConnectServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	s.registerCh <- msg.GetRegister()

	ack := &pb.WorkerMessage{Message: &pb.WorkerMessage_RegisterAck{RegisterAck: &pb.RegisterAck{Accepted: true}}}
	if err := stream.Send(ack); err != nil {
		return err
	}
	if s.execReq != nil {
		if err := stream.Send(&pb.WorkerMessage{Message: &pb.WorkerMessage_Execute{Execute: s.execReq}}); err != nil {
			return err
		}
	}

	// One Recv goroutine at a time (grpc forbids concurrent RecvMsg on a
	// stream); Send from the loop is safe alongside it (grpc allows
	// concurrent SendMsg + RecvMsg on one stream).
	msgCh := make(chan *pb.ConnectorMessage, 8)
	recvErrCh := make(chan error, 1)
	go func() {
		for {
			m, err := stream.Recv()
			if err != nil {
				select {
				case recvErrCh <- err:
				default:
				}
				return
			}
			select {
			case msgCh <- m:
			case <-stream.Context().Done():
				return
			}
		}
	}()

	for {
		select {
		case m := <-msgCh:
			switch mm := m.Message.(type) {
			case *pb.ConnectorMessage_Result:
			case *pb.ConnectorMessage_Done:
				s.doneCh <- mm.Done
				return nil
			}
		case err := <-recvErrCh:
			return err
		case <-s.sendCancel:
			s.sendCancel = nil // fire once; a nil channel disables the case
			if err := stream.Send(&pb.WorkerMessage{Message: &pb.WorkerMessage_Cancel{Cancel: &pb.Cancel{ExecutionId: s.execReq.ExecutionId}}}); err != nil {
				return err
			}
			close(s.cancelSent)
		}
	}
}

func TestRunWorkerInputsOverrideEnvInputs(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("EXECUTION_ID", "exec-merge")
	t.Setenv("INPUT_TARGET", "env-target")
	t.Setenv("INPUT_EXTRA", "env-only")

	srv := newFakeConnectorServer(&pb.ExecuteJob{
		ExecutionId: "exec-merge",
		JobId:       "job-merge",
		Tool:        "nuclei",
		Inputs:      map[string]string{"target": "worker-target"},
	})
	addr := startFakeServer(t, srv)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	inputsCh := make(chan map[string]any, 1)
	adapter := &recordingAdapter{chunk: &connector.Finding{Name: "merged", Severity: "info"}, inputsCh: inputsCh}
	rt := New(connector.New(adapter))
	_, _ = runRuntime(t, rt)
	waitRegister(t, srv)

	select {
	case merged := <-inputsCh:
		if merged["target"] != "worker-target" {
			t.Errorf(`merged["target"] = %v, want worker-target (worker must win over env)`, merged["target"])
		}
		if merged["extra"] != "env-only" {
			t.Errorf(`merged["extra"] = %v, want env-only (env-only keys must survive)`, merged["extra"])
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for adapter inputs")
	}
}

func TestRunCancelAbortsInFlightExecution(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("WORKER_TOKEN", "tok-cancel")
	t.Setenv("EXECUTION_ID", "exec-cancel")

	execReq := &pb.ExecuteJob{ExecutionId: "exec-cancel", JobId: "job-cancel", Tool: "nuclei"}
	sendCancel := make(chan struct{})
	srv := newCancelServer(execReq, sendCancel)
	addr := startFakeServer(t, srv)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	startedCh := make(chan struct{})
	gotCancel := make(chan error, 1)
	adapter := &blockingAdapter{startedCh: startedCh, gotCancel: gotCancel}
	rt := New(connector.New(adapter))
	_, _ = runRuntime(t, rt)

	waitRegisterCh(t, srv.registerCh)

	// Execution is in flight: the cancel map must hold the entry.
	<-startedCh
	rt.cancelsMu.Lock()
	_, inFlight := rt.cancels[execReq.ExecutionId]
	rt.cancelsMu.Unlock()
	if !inFlight {
		t.Fatal("cancel map missing in-flight execution")
	}

	// Worker emits Cancel: the adapter must observe its context cancelled.
	close(sendCancel)
	select {
	case err := <-gotCancel:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("adapter saw ctx err %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("adapter never observed cancellation")
	}

	// The execution must finish with an error Done for the cancelled run.
	select {
	case done := <-srv.doneCh:
		if done.ExecutionId != execReq.ExecutionId {
			t.Errorf("Done.ExecutionId = %q, want %q", done.ExecutionId, execReq.ExecutionId)
		}
		if !strings.Contains(done.Error, "cancelled by worker") {
			t.Errorf("Done.Error = %q, want it to mention the adapter cancel error", done.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Done")
	}

	// Execution finished: the cancel map entry must be gone.
	rt.cancelsMu.Lock()
	_, still := rt.cancels[execReq.ExecutionId]
	rt.cancelsMu.Unlock()
	if still {
		t.Error("cancel map still holds entry after execution finished")
	}
}

// invalidFindingAdapter emits one valid finding, then one that fails
// Validate (empty name) — proves the runtime fail-fasts on contract
// violations instead of silently dropping them.
type invalidFindingAdapter struct{}

func (a *invalidFindingAdapter) Validate(ctx context.Context, inputs map[string]any) error {
	return nil
}
func (a *invalidFindingAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	out <- connector.Finding{Name: "good-finding", Severity: "medium"}
	out <- connector.Finding{Severity: "medium"} // missing Name → invalid
	return nil
}

func TestRunInvalidFindingFailsFast(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("WORKER_TOKEN", "tok-invalid")
	t.Setenv("EXECUTION_ID", "exec-invalid")
	t.Setenv("JOB_ID", "job-invalid")
	t.Setenv("TOOL", "nuclei")

	srv := newFakeConnectorServer(&pb.ExecuteJob{
		ExecutionId: "exec-invalid",
		JobId:       "job-invalid",
		Tool:        "nuclei",
		Inputs:      map[string]string{"target": "https://example.com"},
	})
	addr := startFakeServer(t, srv)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	rt := New(connector.New(&invalidFindingAdapter{}))
	_, _ = runRuntime(t, rt)
	waitRegister(t, srv)

	// The valid finding still ships.
	select {
	case res := <-srv.resultCh:
		if len(res.Findings) != 1 || res.Findings[0].Name != "good-finding" {
			t.Fatalf("first Result = %+v, want one finding named good-finding", res)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first Result")
	}

	// The invalid finding must not stream: the execution terminates with a
	// fatal Done error naming the offending index, not a silent drop.
	select {
	case done := <-srv.doneCh:
		if !strings.Contains(done.Error, "fatal: finding 1 invalid") {
			t.Fatalf("Done.Error = %q, want fatal invalid-finding error at index 1", done.Error)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Done")
	}

	// No further Result may arrive for the invalid finding.
	select {
	case res := <-srv.resultCh:
		t.Fatalf("unexpected extra Result after invalid finding: %+v", res)
	case <-time.After(100 * time.Millisecond):
	}
}
