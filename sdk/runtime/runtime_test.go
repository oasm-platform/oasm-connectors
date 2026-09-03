package runtime

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	pb "github.com/oasm-platform/oasm-connectors/sdk/proto/gen"
	"google.golang.org/grpc"
)

// fakeAdapter emits one chunk and succeeds; mirrors adapter shape used by connectors.
type fakeAdapter struct {
	chunk []byte
	err   error
}

func (a *fakeAdapter) Validate(ctx context.Context, inputs map[string]any) error { return nil }
func (a *fakeAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- []byte) error {
	if a.chunk != nil {
		select {
		case out <- a.chunk:
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
	resultCh   chan []byte
	doneCh     chan *pb.Done
}

func newFakeConnectorServer(exec *pb.ExecuteJob) *fakeConnectorServer {
	return &fakeConnectorServer{
		registerCh: make(chan *pb.Register, 1),
		execReq:    exec,
		resultCh:   make(chan []byte, 1),
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
			s.resultCh <- m.Result.Data
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
	select {
	case reg := <-srv.registerCh:
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

	adapter := &fakeAdapter{chunk: []byte(`{"ok":true}`)}
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
	case data := <-srv.resultCh:
		if string(data) != `{"ok":true}` {
			t.Errorf("Result data = %q, want %q", data, `{"ok":true}`)
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
	// EXECUTION_ID, JOB_ID, TOOL unset — legacy mode must stay intact

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
