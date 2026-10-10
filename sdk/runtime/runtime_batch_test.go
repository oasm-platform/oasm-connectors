package runtime

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	pb "github.com/oasm-platform/oasm-connectors/sdk/proto/gen"
)

// burstAdapter emits n findings back to back, optionally pausing before the
// last one and optionally making finding #invalidAt invalid.
type burstAdapter struct {
	n         int
	pause     time.Duration
	invalidAt int // -1 = none
	descLen   int
}

func (a *burstAdapter) Validate(context.Context, map[string]any) error { return nil }
func (a *burstAdapter) Execute(ctx context.Context, _ map[string]any, out chan<- connector.Finding) error {
	for i := 0; i < a.n; i++ {
		if a.pause > 0 && i == a.n-1 {
			time.Sleep(a.pause)
		}
		f := connector.Finding{Name: fmt.Sprintf("f-%d", i), Severity: "info", Description: strings.Repeat("x", a.descLen)}
		if i == a.invalidAt {
			f.Name = ""
		}
		select {
		case out <- f:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// runBurst runs one execution against a fake worker and returns every Result
// received before Done, plus the Done.
func runBurst(t *testing.T, a *burstAdapter) ([]*pb.Result, *pb.Done) {
	t.Helper()
	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("EXECUTION_ID", "exec-batch")
	srv := newFakeConnectorServer(&pb.ExecuteJob{ExecutionId: "exec-batch", JobId: "job-batch", Tool: "katana"})
	srv.resultCh = make(chan *pb.Result, 1024)
	t.Setenv("WORKER_GRPC_ADDR", startFakeServer(t, srv))
	_, _ = runRuntime(t, New(connector.New(a)))
	waitRegister(t, srv)

	select {
	case done := <-srv.doneCh:
		var results []*pb.Result
		for len(srv.resultCh) > 0 {
			results = append(results, <-srv.resultCh)
		}
		return results, done
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for Done")
		return nil, nil
	}
}

func names(results []*pb.Result) []string {
	var out []string
	for _, r := range results {
		for _, f := range r.Findings {
			out = append(out, f.Name)
		}
	}
	return out
}

func TestRunBatchesFindingsBySize(t *testing.T) {
	results, done := runBurst(t, &burstAdapter{n: 250, invalidAt: -1})
	if done.Error != "" {
		t.Fatalf("Done.Error = %q", done.Error)
	}
	got := names(results)
	if len(got) != 250 || got[0] != "f-0" || got[249] != "f-249" {
		t.Fatalf("streamed %d findings (first %v), want all 250 in order", len(got), got[:min(3, len(got))])
	}
	if len(results) > 10 {
		t.Fatalf("250 findings arrived in %d Result messages, want batching (<=10)", len(results))
	}
	for i, r := range results {
		if len(r.Findings) > maxBatchFindings {
			t.Fatalf("Result %d carries %d findings, cap is %d", i, len(r.Findings), maxBatchFindings)
		}
		if r.ExecutionId != "exec-batch" {
			t.Fatalf("Result %d ExecutionId = %q", i, r.ExecutionId)
		}
	}
}

func TestRunBatchRespectsByteCap(t *testing.T) {
	// 40 findings x ~100 KiB: a count-only batch would blow past the 4 MiB
	// gRPC default message limit on the worker.
	results, done := runBurst(t, &burstAdapter{n: 40, invalidAt: -1, descLen: 100 << 10})
	if done.Error != "" {
		t.Fatalf("Done.Error = %q", done.Error)
	}
	if got := len(names(results)); got != 40 {
		t.Fatalf("streamed %d findings, want 40", got)
	}
	if len(results) < 2 {
		t.Fatalf("got %d Result message(s), want the byte cap to split the batch", len(results))
	}
}

func TestRunFlushesSlowTrickleBeforeDone(t *testing.T) {
	results, done := runBurst(t, &burstAdapter{n: 3, invalidAt: -1, pause: 3 * batchFlushInterval})
	if done.Error != "" {
		t.Fatalf("Done.Error = %q", done.Error)
	}
	if got := names(results); len(got) != 3 {
		t.Fatalf("streamed %v, want 3 findings", got)
	}
	// The first two must have been flushed by the timer while the adapter
	// was still paused, i.e. in a separate message from the last one.
	if len(results) < 2 {
		t.Fatalf("got %d Result message(s), want the interval flush to split the trickle", len(results))
	}
}

func TestRunInvalidFindingShipsValidPrefixThenFails(t *testing.T) {
	results, done := runBurst(t, &burstAdapter{n: 120, invalidAt: 57})
	if !strings.Contains(done.Error, "fatal: finding 57 invalid") {
		t.Fatalf("Done.Error = %q, want fatal invalid at index 57", done.Error)
	}
	got := names(results)
	if len(got) != 57 || got[56] != "f-56" {
		t.Fatalf("streamed %d findings, want exactly the 57 valid ones before the invalid finding", len(got))
	}
}
