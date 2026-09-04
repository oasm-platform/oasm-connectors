package runtime

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	pb "github.com/oasm-platform/oasm-connectors/sdk/proto/gen"
)

// Phase 2 warm pool: ONE stream serves MULTIPLE executions sequentially. The
// SDK must (a) stay alive after the first Done and run the second ExecuteJob
// on the same stream, and (b) apply the per-job config override
// (ExecuteJob.config["oasm_config"]) for reused containers whose env holds
// stale first-run values.

// envRecordingAdapter records the OASM_CONFIG env it observed and the inputs
// it received per execution — the config-override observability seam.
type envRecordingAdapter struct {
	mu     sync.Mutex
	cfgs   []string
	inputs []map[string]any
	chunk  *connector.Finding
}

func (a *envRecordingAdapter) Validate(ctx context.Context, inputs map[string]any) error { return nil }
func (a *envRecordingAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	a.mu.Lock()
	a.cfgs = append(a.cfgs, os.Getenv("OASM_CONFIG"))
	a.inputs = append(a.inputs, inputs)
	a.mu.Unlock()
	if a.chunk != nil {
		select {
		case out <- *a.chunk:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (a *envRecordingAdapter) cfg(i int) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if i < len(a.cfgs) {
		return a.cfgs[i]
	}
	return "<none>"
}

func (a *envRecordingAdapter) input(i int, key string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if i < len(a.inputs) {
		if v, ok := a.inputs[i][key]; ok {
			return v.(string)
		}
	}
	return "<missing>"
}

// twoExecServer sends one ExecuteJob, waits for its Done, then sends a second
// one on the SAME stream and waits for the second Done — mirroring the
// worker's warm-pool reuse flow.
type twoExecServer struct {
	pb.UnimplementedConnectorServiceServer
	registerCh chan *pb.Register
	exec1, ex2 *pb.ExecuteJob
	doneCh     chan *pb.Done
}

func (s *twoExecServer) Connect(stream pb.ConnectorService_ConnectServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	s.registerCh <- msg.GetRegister()
	if err := stream.Send(&pb.WorkerMessage{Message: &pb.WorkerMessage_RegisterAck{RegisterAck: &pb.RegisterAck{Accepted: true}}}); err != nil {
		return err
	}
	if err := stream.Send(&pb.WorkerMessage{Message: &pb.WorkerMessage_Execute{Execute: s.exec1}}); err != nil {
		return err
	}
	for {
		msg, err := stream.Recv()
		if err != nil {
			return err
		}
		switch m := msg.Message.(type) {
		case *pb.ConnectorMessage_Result:
			// findings ignored — the adapter's env/input recording is the seam
		case *pb.ConnectorMessage_Done:
			s.doneCh <- m.Done
			if s.ex2 != nil && m.Done.ExecutionId == s.exec1.ExecutionId {
				// First execution finished: reuse the stream for exec #2.
				if err := stream.Send(&pb.WorkerMessage{Message: &pb.WorkerMessage_Execute{Execute: s.ex2}}); err != nil {
					return err
				}
			} else {
				// Both executions complete: keep the stream OPEN (worker
				// warm-pool behavior — the next ExecuteJob may still arrive).
				<-stream.Context().Done()
				return stream.Context().Err()
			}
		}
	}
}

func TestRunReusesStreamForSecondExecuteWithConfigOverride(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("WORKER_TOKEN", "tok-reuse")
	t.Setenv("EXECUTION_ID", "exec-r1")
	t.Setenv("JOB_ID", "job-r1")
	t.Setenv("TOOL", "nuclei")
	t.Setenv("OASM_CONFIG", `{"rateLimit":5}`) // first-run env config

	srv := &twoExecServer{
		registerCh: make(chan *pb.Register, 1),
		doneCh:     make(chan *pb.Done, 2),
		exec1: &pb.ExecuteJob{
			ExecutionId: "exec-r1",
			JobId:       "job-r1",
			Tool:        "nuclei",
			Inputs:      map[string]string{"target": "https://one.example.com"},
		},
		ex2: &pb.ExecuteJob{
			ExecutionId: "exec-r2",
			JobId:       "job-r2",
			Tool:        "nuclei",
			Inputs:      map[string]string{"target": "https://two.example.com"},
			// Reused container: worker ships the job config in-band — the SDK
			// must override the stale first-run env (rateLimit 5 → 42).
			Config: map[string]string{"oasm_config": `{"rateLimit":42}`},
		},
	}
	addr := startFakeServer(t, srv)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	adapter := &envRecordingAdapter{chunk: &connector.Finding{Name: "f", Severity: "info", MatchedAt: "http://x"}}
	rt := New(connector.New(adapter))
	_, errCh := runRuntime(t, rt)

	reg := waitRegisterCh(t, srv.registerCh)
	if reg.ExecutionId != "exec-r1" {
		t.Fatalf("Register.ExecutionId = %q, want exec-r1", reg.ExecutionId)
	}

	// Both executions must complete on the same stream (two Dones).
	for i, wantExec := range []string{"exec-r1", "exec-r2"} {
		select {
		case done := <-srv.doneCh:
			if done.ExecutionId != wantExec {
				t.Fatalf("Done #%d ExecutionId = %q, want %q (stream reuse)", i+1, done.ExecutionId, wantExec)
			}
			if done.Error != "" {
				t.Fatalf("Done #%d Error = %q, want empty", i+1, done.Error)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out waiting for Done #%d (exec %s)", i+1, wantExec)
		}
	}

	// The second execution's config override reached the adapter.
	if got := adapter.cfg(1); got != `{"rateLimit":42}` {
		t.Fatalf("adapter saw OASM_CONFIG=%q on execution #2, want the in-band override {\"rateLimit\":42}", got)
	}
	// Per-job inputs still merge per execution.
	if got := adapter.input(1, "target"); got != "https://two.example.com" {
		t.Fatalf("execution #2 target = %q, want https://two.example.com", got)
	}

	// Run must NOT exit after the second Done until the stream closes.
	select {
	case err := <-errCh:
		t.Fatalf("Run returned early: %v (warm pool keeps the stream open)", err)
	case <-time.After(150 * time.Millisecond):
	}
}
