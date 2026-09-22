package logging

import "testing"

// TestPrintSample is not an assertion — it prints what a connector's container
// log looks like, including the real ANSI colours, so the format can be eyeballed
// with:
//
//	OASM_LOG_COLOR=always LOG_LEVEL=debug go test ./logging/ -run TestPrintSample -v
func TestPrintSample(t *testing.T) {
	t.Setenv("OASM_LOG_COLOR", "always")
	t.Setenv("LOG_LEVEL", "debug")
	l := New("runtime").
		WithFields("execution_id", "8f2c…", "job_id", "job-42", "tool", "nmap").
		WithTraceID("tr-abc123")
	l.Info("connector starting: pid=1 inputs=target=example.com")
	l.Debug("dialing worker addr=10.0.0.5:50051 tls=false")
	l.Success("registered with worker: addr=10.0.0.5:50051")
	l.Info("execute start: inputs=target=example.com config=ports=1-1024")
	l.Debug("streamed result 1 name=\"open tcp/443 (https)\" severity=info")
	l.Warn("execution cancelled but adapter returned nil; reporting canceled: results=0 elapsed=1.2s")
	l.Success("execution done: results=17 elapsed=42s")
	l.Error("adapter error after 0 result(s) in 3s: fatal: nmap: cannot resolve \"nope.invalid\"")
}
