package connector

import (
	"fmt"
	"testing"
)

func TestTailWriterKeepsLastLimitBytes(t *testing.T) {
	w := NewTailWriter(4)
	fmt.Fprint(w, "ab")
	fmt.Fprint(w, "cdef")
	if got := w.String(); got != "cdef" {
		t.Fatalf("String() = %q, want the last 4 bytes %q", got, "cdef")
	}
}

func TestTailWriterTrimsSurroundingSpace(t *testing.T) {
	w := NewTailWriter(64)
	n, err := w.Write([]byte("\n  boom \n"))
	if err != nil || n != 9 {
		t.Fatalf("Write = %d, %v; want full length, nil", n, err)
	}
	if got := w.String(); got != "boom" {
		t.Fatalf("String() = %q, want %q", got, "boom")
	}
}
