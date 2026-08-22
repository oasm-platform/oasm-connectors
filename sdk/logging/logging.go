package logging

import (
	"fmt"
	"log"
)

// Logger forwards logs to Worker via channel (stub) and falls back to std log.
// ponytail: ceiling is channel/gRPC forward to Worker; currently channel sink + local log.
type Logger struct {
	prefix  string
	traceID string
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
	return &Logger{prefix: l.prefix, traceID: traceID, sink: l.sink}
}

// WithSink returns a derived Logger that forwards formatted lines to sink.
func (l *Logger) WithSink(sink chan []byte) *Logger {
	return &Logger{prefix: l.prefix, traceID: l.traceID, sink: sink}
}

// TraceID returns the trace identifier.
func (l *Logger) TraceID() string { return l.traceID }

func (l *Logger) format(level, msg string) string {
	if l.traceID != "" {
		return fmt.Sprintf("[%s] [%s] trace_id=%s %s", l.prefix, level, l.traceID, msg)
	}
	return fmt.Sprintf("[%s] [%s] %s", l.prefix, level, msg)
}

func (l *Logger) write(level, msg string) {
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
func (l *Logger) Info(msg string) { l.write("INFO", msg) }

// Infof logs formatted at INFO level.
func (l *Logger) Infof(format string, args ...any) { l.write("INFO", fmt.Sprintf(format, args...)) }

// Error logs at ERROR level.
func (l *Logger) Error(msg string) { l.write("ERROR", msg) }

// Errorf logs formatted at ERROR level.
func (l *Logger) Errorf(format string, args ...any) { l.write("ERROR", fmt.Sprintf(format, args...)) }

// Debug logs at DEBUG level.
func (l *Logger) Debug(msg string) { l.write("DEBUG", msg) }

// Debugf logs formatted at DEBUG level.
func (l *Logger) Debugf(format string, args ...any) { l.write("DEBUG", fmt.Sprintf(format, args...)) }
