package connector

import "strings"

// TailWriter is an io.Writer that keeps only the last limit bytes written —
// for capturing a scanner's stderr tail without unbounded memory.
type TailWriter struct {
	buf   []byte
	limit int
}

// NewTailWriter returns a TailWriter keeping at most limit bytes.
func NewTailWriter(limit int) *TailWriter { return &TailWriter{limit: limit} }

// Write appends p, dropping the oldest bytes beyond the limit. Never fails.
func (w *TailWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	if len(w.buf) > w.limit {
		w.buf = w.buf[len(w.buf)-w.limit:]
	}
	return len(p), nil
}

// String returns the captured tail, whitespace-trimmed.
func (w *TailWriter) String() string { return strings.TrimSpace(string(w.buf)) }
