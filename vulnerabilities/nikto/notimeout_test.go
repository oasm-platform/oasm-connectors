package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// --- no connector-imposed time ceiling ---
//
// Vulnerability scans routinely run for hours: a full nikto CGI sweep against a
// slow host, or a deliberately stalling target, is a legitimate long job rather
// than a failure. The adapter therefore imposes NO ceiling of its own. A scan
// ends when nikto finishes, when the operator sets maxTime, or when the caller's
// context is cancelled (the Worker does that at the job's timeoutSeconds).
//
// These tests pin that contract: nothing in this package may end a scan early.

// An unset maxTime must NOT be turned into an implicit budget. Sending -maxtime
// would cap a caller who never asked for a cap.
func TestBuildNiktoArgs_NoImplicitMaxTime(t *testing.T) {
	args := buildNiktoArgs("https://example.com", &niktoConfig{}, "/tmp/nikto.conf")
	if hasFlag(args, "-maxtime") {
		t.Fatalf("no -maxtime may be injected when maxTime is unset, got %v", args)
	}
}

// An explicit maxTime is passed through verbatim — operator intent is honoured,
// and the adapter does not reinterpret it.
func TestBuildNiktoArgs_ExplicitMaxTimePassedThrough(t *testing.T) {
	for _, mt := range []string{"30m", "1h", "600s", "3600"} {
		args := buildNiktoArgs("https://example.com", &niktoConfig{MaxTime: mt}, "/tmp/nikto.conf")
		if v := argValue(args, "-maxtime"); v != mt {
			t.Errorf("maxTime %q: -maxtime = %q", mt, v)
		}
	}
}

// A long-running scan must not be killed by the adapter. The fake streams
// findings slowly forever; the adapter must still be running after a wait that
// any self-imposed ceiling would have fired within.
func TestNiktoExecute_NoSelfImposedTimeout(t *testing.T) {
	bin := ensureFakeNikto(t)
	t.Setenv("FAKE_MODE", "slow-many")
	t.Setenv("NIKTO_BIN", bin)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan connector.Finding, 1024)
	done := make(chan error, 1)
	go func() {
		done <- NiktoAdapter{}.Execute(ctx, map[string]any{"target": "example.com"}, out)
	}()

	// Let it stream for a while. A self-imposed ceiling would fire in this
	// window and return.
	time.Sleep(2 * time.Second)

	select {
	case err := <-done:
		t.Fatalf("Execute returned on its own after 2s (err=%v); the adapter must not impose a ceiling", err)
	default:
	}

	// Cancelling the caller's context is what stops it.
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Execute = nil after cancellation, want the context error")
		} else if !strings.Contains(err.Error(), "context canceled") {
			t.Errorf("Execute = %v, want a context cancellation error", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Execute did not stop after cancellation")
	}
}

// Cancellation is reported faithfully: the caller cancelled, so the adapter
// surfaces it rather than pretending the scan completed.
func TestNiktoExecute_CancelIsReported(t *testing.T) {
	bin := ensureFakeNikto(t)
	t.Setenv("FAKE_MODE", "hang")
	t.Setenv("NIKTO_BIN", bin)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	out := make(chan connector.Finding, 8)
	err := NiktoAdapter{}.Execute(ctx, map[string]any{"target": "example.com"}, out)
	if err == nil {
		t.Fatal("a cancelled scan must report an error")
	}
	if !strings.Contains(err.Error(), "context") && ctx.Err() == nil {
		t.Errorf("error = %v, want the context error", err)
	}
}

// Findings streamed before a cancellation are still delivered: the adapter does
// not retract them, and the caller decides what partial results are worth.
func TestNiktoExecute_PartialFindingsDeliveredBeforeCancel(t *testing.T) {
	bin := ensureFakeNikto(t)
	t.Setenv("FAKE_MODE", "slow-many")
	t.Setenv("NIKTO_BIN", bin)

	ctx, cancel := context.WithCancel(context.Background())
	out := make(chan connector.Finding, 1024)
	done := make(chan error, 1)
	go func() {
		done <- NiktoAdapter{}.Execute(ctx, map[string]any{"target": "example.com"}, out)
	}()

	// Wait for at least a few findings, then cancel mid-stream.
	deadline := time.After(10 * time.Second)
	got := 0
	for got < 3 {
		select {
		case <-out:
			got++
		case <-deadline:
			t.Fatalf("only %d finding(s) streamed before the deadline", got)
		}
	}
	cancel()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("Execute did not return after cancel")
	}
	close(out)
	rest := 0
	for range out {
		rest++
	}
	if got+rest < 3 {
		t.Errorf("delivered %d findings, want at least the 3 seen", got+rest)
	}
	t.Logf("delivered %d finding(s) across the cancellation", got+rest)
}

// The zero config must carry no maxTime, since "unset" now means "no limit"
// rather than "use a built-in value".
func TestZeroConfigHasNoMaxTime(t *testing.T) {
	cfg := &niktoConfig{}
	if cfg.MaxTime != "" {
		t.Fatalf("zero config MaxTime = %q, want empty", cfg.MaxTime)
	}
	args := buildNiktoArgs("https://example.com", cfg, "/c")
	if hasFlag(args, "-maxtime") {
		t.Errorf("zero config produced -maxtime: %v", args)
	}
}
