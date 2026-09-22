package logging

import (
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
)

// Logger forwards logs to Worker via channel (stub) and falls back to std log.
// ponytail: ceiling is channel/gRPC forward to Worker; currently channel sink + local log.
//
// Output is a human-readable, ANSI-coloured line:
//
//	[runtime] [INFO]  trace_id=… execution_id=… job_id=… message
//
// Levels are DEBUG, INFO, SUCCESS, WARN, ERROR. Colour is applied only when
// stderr is a terminal (see colorEnabled), so the same binary stays plain text
// in a container log, a CI transcript or a pipe.
type Logger struct {
	prefix  string
	traceID string
	fields  []string
	sink    chan []byte
}

// New creates a Logger with prefix.
func New(prefix string) *Logger { return &Logger{prefix: prefix} }

// NewWithTraceID creates a Logger with prefix and traceID.
func NewWithTraceID(prefix, traceID string) *Logger {
	return &Logger{prefix: prefix, traceID: traceID}
}

// WithTraceID returns a derived Logger with traceID set.
func (l *Logger) WithTraceID(traceID string) *Logger {
	c := l.clone()
	c.traceID = traceID
	return c
}

// SetTraceID mutates the receiver's trace id in place. Used by the runtime once
// TRACE_ID is known (env-loaded after the logger is constructed) so every later
// line — including those emitted from execution goroutines — carries it.
func (l *Logger) SetTraceID(traceID string) { l.traceID = traceID }

// WithFields returns a derived Logger that prints key=value pairs on every line.
// Callers pass alternating keys and values; an odd trailing key is ignored.
// Fields are for correlation (execution_id, job_id, tool) — never secrets.
func (l *Logger) WithFields(kv ...string) *Logger {
	c := l.clone()
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i] == "" {
			continue
		}
		c.fields = append(c.fields, fmt.Sprintf("%s=%s", kv[i], kv[i+1]))
	}
	return c
}

// WithSink returns a derived Logger that forwards formatted lines to sink.
func (l *Logger) WithSink(sink chan []byte) *Logger {
	c := l.clone()
	c.sink = sink
	return c
}

func (l *Logger) clone() *Logger {
	c := *l
	c.fields = append([]string(nil), l.fields...)
	return &c
}

// TraceID returns the trace identifier.
func (l *Logger) TraceID() string { return l.traceID }

func (l *Logger) format(level, msg string) string {
	var b strings.Builder
	b.WriteString(paint(cDim, "["+l.prefix+"]"))
	b.WriteString(" ")
	b.WriteString(paint(levelColor(level), fmt.Sprintf("[%-7s]", level)))
	if l.traceID != "" {
		b.WriteString(" " + paint(cDim, "trace_id="+l.traceID))
	}
	for _, f := range l.fields {
		b.WriteString(" " + paint(cDim, f))
	}
	b.WriteString(" " + paint(cBright, msg))
	return b.String()
}

// levelEnabled reports whether a level is emitted. DEBUG is opt-in via
// LOG_LEVEL=debug (or OASM_LOG_LEVEL=debug), read per call so a reused warm-pool
// container honors the env it was started with and tests can flip it per case.
func levelEnabled(level string) bool {
	if level != lvlDebug {
		return true
	}
	v := os.Getenv("LOG_LEVEL")
	if v == "" {
		v = os.Getenv("OASM_LOG_LEVEL")
	}
	return strings.EqualFold(strings.TrimSpace(v), "debug")
}

func (l *Logger) write(level, msg string) {
	if !levelEnabled(level) {
		return
	}
	line := l.format(level, msg)
	if l.sink != nil {
		select {
		case l.sink <- []byte(line):
		default:
		}
		return
	}
	log.Print(line)
}

// Info logs at INFO level.
func (l *Logger) Info(msg string) { l.write(lvlInfo, msg) }

// Infof logs formatted at INFO level.
func (l *Logger) Infof(format string, args ...any) { l.write(lvlInfo, fmt.Sprintf(format, args...)) }

// Success logs at SUCCESS level — a terminal, good-outcome line (job done,
// registration accepted). Distinct from Info so a scan result stands out in a
// wall of progress lines.
func (l *Logger) Success(msg string) { l.write(lvlSuccess, msg) }

// Successf logs formatted at SUCCESS level.
func (l *Logger) Successf(format string, args ...any) {
	l.write(lvlSuccess, fmt.Sprintf(format, args...))
}

// Warn logs at WARN level.
func (l *Logger) Warn(msg string) { l.write(lvlWarn, msg) }

// Warnf logs formatted at WARN level.
func (l *Logger) Warnf(format string, args ...any) { l.write(lvlWarn, fmt.Sprintf(format, args...)) }

// Error logs at ERROR level.
func (l *Logger) Error(msg string) { l.write(lvlError, msg) }

// Errorf logs formatted at ERROR level.
func (l *Logger) Errorf(format string, args ...any) { l.write(lvlError, fmt.Sprintf(format, args...)) }

// Debug logs at DEBUG level.
func (l *Logger) Debug(msg string) { l.write(lvlDebug, msg) }

// Debugf logs formatted at DEBUG level.
func (l *Logger) Debugf(format string, args ...any) { l.write(lvlDebug, fmt.Sprintf(format, args...)) }

// Summarize renders values as a compact, deterministic `k=v` list for logs:
// keys are sorted (stable diffs across runs), secrets are redacted, and long
// values are truncated. nil/empty input yields "-" so a line never ends bare.
// Generic over the map's value type so the SDK can log its own string maps
// (ExecuteJob.Inputs/Config) without copying them.
func Summarize[V any](values map[string]V, maxValue int) string {
	if len(values) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		if sensitiveKey(k) {
			parts = append(parts, k+"=<redacted>")
			continue
		}
		parts = append(parts, k+"="+Truncate(renderValue(values[k]), maxValue))
	}
	return strings.Join(parts, " ")
}

// sensitiveKey reports whether a config/input key may hold a credential. The
// job's inputs and config are logged for tracing, and those logs are persisted
// by the platform, so credentials must never reach them.
func sensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, tok := range []string{"token", "secret", "password", "passwd", "apikey", "api_key", "authorization", "auth", "credential", "cookie", "session", "private"} {
		if strings.Contains(k, tok) {
			return true
		}
	}
	return false
}

// renderValue formats one value for a log line without quoting plain strings.
func renderValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "<nil>"
	case string:
		return strings.ReplaceAll(strings.ReplaceAll(t, "\n", `\n`), "\r", "")
	default:
		return fmt.Sprintf("%v", t)
	}
}

// Truncate caps s at max runes, marking the cut so a log line never lies about
// being complete. max <= 0 returns s unchanged.
func Truncate(s string, max int) string {
	if max <= 0 {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// Keys returns the sorted key list of a map, for logging "which inputs arrived"
// without dumping their values.
func Keys[V any](values map[string]V) string {
	if len(values) == 0 {
		return "-"
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ",")
}
