package logging

import (
	"strings"
	"testing"
)

func TestLoggerWritesWithTraceID(t *testing.T) {
	sink := make(chan []byte, 4)
	l := New("test").WithTraceID("trace-abc").WithSink(sink)
	l.Info("hello")
	got := string(<-sink)
	if !strings.Contains(got, "trace-abc") {
		t.Fatalf("want trace_id in log, got %q", got)
	}
	if !strings.Contains(got, "hello") {
		t.Fatalf("want message in log, got %q", got)
	}
	if !strings.Contains(got, "test") {
		t.Fatalf("want prefix in log, got %q", got)
	}
}

func TestLoggerWithoutTraceID(t *testing.T) {
	sink := make(chan []byte, 4)
	l := New("worker").WithSink(sink)
	l.Infof("count=%d", 42)
	got := string(<-sink)
	if !strings.Contains(got, "count=42") {
		t.Fatalf("want formatted message, got %q", got)
	}
}

func TestLoggerNewWithTraceID(t *testing.T) {
	sink := make(chan []byte, 4)
	l := NewWithTraceID("ns", "tid-123").WithSink(sink)
	if l.TraceID() != "tid-123" {
		t.Fatalf("want tid-123, got %s", l.TraceID())
	}
	l.Error("boom")
	got := string(<-sink)
	if !strings.Contains(got, "tid-123") || !strings.Contains(got, "ERROR") {
		t.Fatalf("want trace and level, got %q", got)
	}
}
