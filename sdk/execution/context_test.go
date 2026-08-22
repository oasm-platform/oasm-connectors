package execution

import (
	"context"
	"testing"
	"time"
)

func TestContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ec := NewContext(ctx, "exec-1", map[string]any{"target": "https://example.com"})
	cancel()
	select {
	case <-ec.Done():
	default:
		t.Fatal("should be done after cancel")
	}
}

func TestStreamEmits(t *testing.T) {
	ec := NewContext(context.Background(), "exec-1", nil)
	ch := ec.Stream()
	ec.Emit([]byte(`hello`))
	if got := <-ch; string(got) != "hello" {
		t.Fatalf("got %s", got)
	}
}

func TestContextPreservesFields(t *testing.T) {
	inputs := map[string]any{"target": "https://example.com"}
	ec := NewContext(context.Background(), "exec-42", inputs)
	if ec.ExecutionID != "exec-42" {
		t.Fatalf("want exec-42, got %s", ec.ExecutionID)
	}
	if ec.Inputs["target"] != "https://example.com" {
		t.Fatalf("inputs not preserved")
	}
}

func TestEmitRespectsCancellation(t *testing.T) {
	ec := NewContext(context.Background(), "exec-1", nil)
	ec.Cancel()
	select {
	case <-ec.Done():
	default:
		t.Fatal("should be done after Cancel()")
	}
	// Emit after cancel must not block
	done := make(chan struct{})
	go func() { ec.Emit([]byte("x")); close(done) }()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Emit blocked after cancel")
	}
}

func TestChunkJSON(t *testing.T) {
	data := []byte("abcdef")
	chunks := ChunkJSON(data, 2)
	if len(chunks) != 3 {
		t.Fatalf("want 3 chunks, got %d", len(chunks))
	}
	if string(chunks[0]) != "ab" || string(chunks[2]) != "ef" {
		t.Fatalf("chunk mismatch: %v", chunks)
	}
	if len(ChunkJSON(nil, 10)) != 0 {
		t.Fatal("nil should give 0 chunks")
	}
}
