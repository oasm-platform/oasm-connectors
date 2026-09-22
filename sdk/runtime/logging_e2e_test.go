package runtime

import (
	"bytes"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	pb "github.com/oasm-platform/oasm-connectors/sdk/proto/gen"
)

// TestExecuteLogsAreTraceable pins the tracing contract of a connector's
// container log: one execution must leave its identity, the inputs the adapter
// actually saw, the first emitted finding and the terminal outcome — all on
// lines a warm-pool container shares with every other job.
func TestExecuteLogsAreTraceable(t *testing.T) {
	// LOG_LEVEL=debug so the preview lines, which are the deepest trace, are on.
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("EXECUTION_ID", "exec-log")
	t.Setenv("JOB_ID", "job-log")
	t.Setenv("TOOL", "nmap")
	t.Setenv("TRACE_ID", "trace-log")
	t.Setenv("OASM_CONFIG", `{"token":"super-secret","ports":"80"}`)

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	srv := newFakeConnectorServer(&pb.ExecuteJob{
		ExecutionId: "exec-log",
		JobId:       "job-log",
		Tool:        "nmap",
		Image:       "ghcr.io/oasm-platform/connector-nmap:7.97",
		Inputs:      map[string]string{"target": "example.com", "token": "leak-me"},
		Config:      map[string]string{"oasm_config": `{"ports":"443"}`},
	})
	t.Setenv("WORKER_GRPC_ADDR", startFakeServer(t, srv))

	adapter := &fakeAdapter{chunk: &connector.Finding{Name: "open tcp/443 (https)", Severity: "info", MatchedAt: "example.com:443"}}
	_, _ = runRuntime(t, New(connector.New(adapter)))

	select {
	case <-srv.doneCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for Done")
	}
	// The log write happens just before Done is returned, so wait for the
	// terminal line rather than reading a buffer that may still be filling.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "execution done") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	logs := buf.String()

	for _, want := range []string{
		"trace_id=trace-log",
		"execution_id=exec-log",
		"job_id=job-log",
		"tool=nmap",
		"image=ghcr.io/oasm-platform/connector-nmap:7.97",
		"execute start:",
		"target=example.com",
		"effective inputs:",
		"config override applied:",
		"first finding:",
		`"open tcp/443 (https)"`,
		"streamed result 1",
		"emitted preview:",
		"execution done: results=1",
		"SUCCESS",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("container log missing %q\n--- log ---\n%s", want, logs)
		}
	}
	// Credentials are persisted by the platform: they must never appear.
	for _, leak := range []string{"leak-me", "super-secret"} {
		if strings.Contains(logs, leak) {
			t.Errorf("secret %q leaked into the container log\n--- log ---\n%s", leak, logs)
		}
	}
	if !strings.Contains(logs, "<redacted>") {
		t.Errorf("expected redaction markers for credential-shaped inputs\n--- log ---\n%s", logs)
	}
}

// TestExecuteLogsFailureContext: a failing job's log must say which execution
// failed, how far it got, and why — that is what an operator traces.
func TestExecuteLogsFailureContext(t *testing.T) {
	t.Setenv("EXECUTION_ID", "exec-fail")
	t.Setenv("JOB_ID", "job-fail")
	t.Setenv("TOOL", "nmap")

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	srv := newFakeConnectorServer(&pb.ExecuteJob{ExecutionId: "exec-fail", JobId: "job-fail", Tool: "nmap"})
	t.Setenv("WORKER_GRPC_ADDR", startFakeServer(t, srv))

	_, _ = runRuntime(t, New(connector.New(&fakeAdapter{err: errors.New("fatal: nmap: unrecognized option")})))

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "adapter error") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	logs := buf.String()
	for _, want := range []string{"execution_id=exec-fail", "adapter error after 0 result(s)", "unrecognized option", "results=0"} {
		if !strings.Contains(logs, want) {
			t.Errorf("failure log missing %q\n--- log ---\n%s", want, logs)
		}
	}
}
