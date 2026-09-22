package logging

import (
	"strings"
	"testing"
)

// TestLoggerWritesWithTraceID
func TestLoggerWritesWithTraceID(t *testing.T) {
	t.Setenv("OASM_LOG_COLOR", "never")
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
	t.Setenv("OASM_LOG_COLOR", "never")
	sink := make(chan []byte, 4)
	l := New("worker").WithSink(sink)
	l.Infof("count=%d", 42)
	got := string(<-sink)
	if !strings.Contains(got, "count=42") {
		t.Fatalf("want formatted message, got %q", got)
	}
}

func TestLoggerNewWithTraceID(t *testing.T) {
	t.Setenv("OASM_LOG_COLOR", "never")
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

// TestWithFieldsDecoratesEveryLine: correlation fields ride on every line, so a
// job's logs can be grepped out of a warm-pool container's shared log stream.
func TestWithFieldsDecoratesEveryLine(t *testing.T) {
	sink := make(chan []byte, 4)
	l := New("runtime").WithFields("execution_id", "e-1", "job_id", "j-2", "tool", "nmap").WithSink(sink)
	l.Info("first")
	l.Errorf("second %d", 2)
	for i, want := range []string{"first", "second 2"} {
		line := string(<-sink)
		if !strings.Contains(line, want) {
			t.Fatalf("line %d = %q, want it to contain %q", i, line, want)
		}
		for _, field := range []string{"execution_id=e-1", "job_id=j-2", "tool=nmap"} {
			if !strings.Contains(line, field) {
				t.Fatalf("line %d missing %q: %q", i, field, line)
			}
		}
	}
}

// TestWithFieldsIsImmutable: deriving a logger must not mutate its parent — the
// Runtime keeps one base logger and derives a per-execution one from it.
func TestWithFieldsIsImmutable(t *testing.T) {
	sink := make(chan []byte, 4)
	base := New("runtime").WithSink(sink)
	child := base.WithFields("job_id", "j-1")
	child.Info("child")
	if got := string(<-sink); !strings.Contains(got, "job_id=j-1") {
		t.Fatalf("child line missing field: %q", got)
	}
	base.Info("parent")
	if got := string(<-sink); strings.Contains(got, "job_id") {
		t.Fatalf("parent logger must not inherit child fields: %q", got)
	}
}

// TestSetTraceIDAppliesToLaterLines: Run learns TRACE_ID from the environment
// after the logger exists, and every subsequent line must carry it.
func TestSetTraceIDAppliesToLaterLines(t *testing.T) {
	sink := make(chan []byte, 4)
	l := New("runtime").WithSink(sink)
	l.Info("before")
	if got := string(<-sink); strings.Contains(got, "trace_id") {
		t.Fatalf("trace id must be absent before it is known: %q", got)
	}
	l.SetTraceID("tr-9")
	l.Info("after")
	if got := string(<-sink); !strings.Contains(got, "trace_id=tr-9") {
		t.Fatalf("trace id missing after SetTraceID: %q", got)
	}
}

// TestDebugIsOptIn: DEBUG is silent by default so shipped connectors do not
// spam, and enabled by LOG_LEVEL=debug (or OASM_LOG_LEVEL).
func TestDebugIsOptIn(t *testing.T) {
	t.Setenv("LOG_LEVEL", "")
	t.Setenv("OASM_LOG_LEVEL", "")
	sink := make(chan []byte, 4)
	l := New("runtime").WithSink(sink)
	l.Debug("quiet")
	select {
	case got := <-sink:
		t.Fatalf("debug must be silent by default, got %q", got)
	default:
	}

	t.Setenv("OASM_LOG_LEVEL", "DEBUG")
	l.Debug("loud")
	select {
	case got := <-sink:
		if line := string(got); !strings.Contains(line, "loud") || !strings.Contains(line, "DEBUG") {
			t.Fatalf("want debug line, got %q", line)
		}
	default:
		t.Fatal("OASM_LOG_LEVEL=DEBUG must enable debug lines")
	}
}

func TestSummarize(t *testing.T) {
	// Sorted keys, secrets redacted, long values truncated, empty map "-".
	got := Summarize(map[string]any{"target": "example.com", "token": "super-secret", "note": strings.Repeat("x", 40)}, 12)
	for _, want := range []string{"note=" + strings.Repeat("x", 12) + "…", "target=example.com", "token=<redacted>"} {
		if !strings.Contains(got, want) {
			t.Fatalf("summary %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "super-secret") {
		t.Fatalf("secret leaked into log line: %q", got)
	}
	if Summarize(map[string]string{}, 10) != "-" {
		t.Fatal("empty map must render as -")
	}
	// Generic over value type: the SDK logs its own map[string]string payloads.
	if got := Summarize(map[string]string{"password": "p", "target": "t"}, 10); strings.Contains(got, "p") && !strings.Contains(got, "<redacted>") {
		t.Fatalf("string map secret leaked: %q", got)
	}
}

func TestKeys(t *testing.T) {
	if got := Keys(map[string]string{"b": "1", "a": "2"}); got != "a,b" {
		t.Fatalf("want a,b got %q", got)
	}
	if got := Keys(map[string]any{}); got != "-" {
		t.Fatalf("want - got %q", got)
	}
}

// TestColorAlwaysPaintsLevels: OASM_LOG_COLOR=always forces ANSI even when
// stderr is not a terminal (a TTY-aware log viewer), and each level gets its own
// SGR colour so scans are readable at a glance.
func TestColorAlwaysPaintsLevels(t *testing.T) {
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("OASM_LOG_COLOR", "always")
	sink := make(chan []byte, 8)
	l := New("runtime").WithSink(sink)
	l.Debug("d")
	l.Info("i")
	l.Success("s")
	l.Warn("w")
	l.Error("e")

	want := []struct{ level, color, msg string }{
		{"DEBUG", "2", "d"}, {"INFO", "36", "i"}, {"SUCCESS", "32", "s"}, {"WARN", "33", "w"}, {"ERROR", "31", "e"},
	}
	for _, w := range want {
		line := string(<-sink)
		if !strings.Contains(line, "\x1b["+w.color+"m") {
			t.Errorf("%s line missing colour %q: %q", w.level, w.color, line)
		}
		if !strings.Contains(line, w.level) {
			t.Errorf("%s line missing level label: %q", w.level, line)
		}
		// Every coloured span is closed immediately, so a log viewer never
		// inherits a colour into unrelated output.
		if !strings.HasSuffix(line, "\x1b[0m") || strings.Count(line, "\x1b[0m") < 3 {
			t.Errorf("%s line spans not reset-terminated: %q", w.level, line)
		}
	}
}

// TestColorNeverIsPlain: an explicit never (and NO_COLOR) must emit no escape
// codes at all — this is what keeps the Worker's captured container log clean.
func TestColorNeverIsPlain(t *testing.T) {
	sink := make(chan []byte, 4)
	l := New("runtime").WithSink(sink)

	t.Setenv("OASM_LOG_COLOR", "never")
	l.Error("boom")
	if line := string(<-sink); strings.Contains(line, "\x1b[") {
		t.Fatalf("escape codes leaked with OASM_LOG_COLOR=never: %q", line)
	}

	// NO_COLOR (the cross-tool convention) wins over auto-detection.
	t.Setenv("OASM_LOG_COLOR", "")
	t.Setenv("NO_COLOR", "1")
	l.Error("boom")
	if line := string(<-sink); strings.Contains(line, "\x1b[") {
		t.Fatalf("escape codes leaked with NO_COLOR set: %q", line)
	}
}

// TestColorOffWhenNotATerminal: the default path. Tests run with stderr captured
// (not a TTY), which is exactly the container/CI case that must stay plain.
func TestColorOffWhenNotATerminal(t *testing.T) {
	t.Setenv("OASM_LOG_COLOR", "")
	t.Setenv("NO_COLOR", "")
	if colorEnabled() {
		t.Skip("stderr is a real terminal in this environment; covered by the explicit never test")
	}
	sink := make(chan []byte, 4)
	New("runtime").WithSink(sink).Info("plain")
	if line := string(<-sink); strings.Contains(line, "\x1b[") {
		t.Fatalf("escape codes leaked without a terminal: %q", line)
	}
}

// TestSuccessLevelIsDistinct pins the added level: a job's outcome line is
// grep-able as SUCCESS and coloured green, not folded into INFO.
func TestSuccessLevelIsDistinct(t *testing.T) {
	t.Setenv("OASM_LOG_COLOR", "never")
	sink := make(chan []byte, 4)
	New("runtime").WithSink(sink).Successf("execution done: results=%d", 3)
	line := string(<-sink)
	if !strings.Contains(line, "SUCCESS") || !strings.Contains(line, "results=3") {
		t.Fatalf("want a SUCCESS line with the message, got %q", line)
	}
}
