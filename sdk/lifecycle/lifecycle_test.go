package lifecycle

import (
	"context"
	"testing"
)

func TestLifecycleTransitions(t *testing.T) {
	lc := New()
	if lc.State() != StateInit {
		t.Fatalf("want init, got %s", lc.State())
	}
	if err := lc.Connect(context.Background(), "localhost:50051"); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if lc.State() != StateReady {
		t.Fatalf("want ready, got %s", lc.State())
	}
	if err := lc.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if lc.State() != StateRunning {
		t.Fatalf("want running, got %s", lc.State())
	}
	lc.Shutdown()
	if lc.State() != StateShutdown {
		t.Fatalf("want shutdown, got %s", lc.State())
	}
}

func TestLifecycleInvalidTransitions(t *testing.T) {
	lc := New()
	if err := lc.Start(); err == nil {
		t.Fatal("want error: init -> running invalid")
	}
	if err := lc.Stop(); err == nil {
		t.Fatal("want error: init -> shutdown via Stop invalid")
	}
	if err := lc.Connect(context.Background(), "x"); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	// ready -> shutdown via Stop is invalid (must be running -> shutdown)
	if err := lc.Stop(); err == nil {
		t.Fatal("want error: ready -> shutdown via Stop invalid")
	}
	// Shutdown is idempotent
	lc.Shutdown()
	if lc.State() != StateShutdown {
		t.Fatalf("want shutdown, got %s", lc.State())
	}
	lc.Shutdown() // second call must not panic
	if err := lc.Connect(context.Background(), "x"); err == nil {
		t.Fatal("want error: shutdown -> ready invalid")
	}
	if err := lc.Start(); err == nil {
		t.Fatal("want error: shutdown -> running invalid")
	}
}

func TestLifecycleConnectIdempotentGuard(t *testing.T) {
	lc := New()
	_ = lc.Connect(context.Background(), "localhost:50051")
	if err := lc.Connect(context.Background(), "localhost:50051"); err == nil {
		t.Fatal("want error on second Connect (ready -> ready)")
	}
}
