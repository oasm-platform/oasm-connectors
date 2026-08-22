package transport

import (
	"os"
	"strings"
	"testing"
)

func TestDialInsecure(t *testing.T) {
	c, err := Dial("localhost:0", DialOpts{Insecure: true})
	if err != nil {
		t.Fatalf("expected dial to succeed (lazy), got %v", err)
	}
	if c != nil {
		_ = c.Close()
	}
}

func TestDialRequiresTarget(t *testing.T) {
	if _, err := Dial("", DialOpts{Insecure: true}); err == nil {
		t.Fatal("expected error for empty target")
	}
}

// Additional leak guard — transport must not import Core/Postgres.
func TestTransportDoesNotLeakCore(t *testing.T) {
	src, err := os.ReadFile("transport.go")
	if err != nil {
		t.Fatalf("read transport.go: %v", err)
	}
	s := string(src)
	if strings.Contains(s, "core-api") || strings.Contains(s, "postgres") {
		t.Fatal("transport must not leak Core")
	}
	// also check mtls.go
	if data, err := os.ReadFile("mtls.go"); err == nil {
		ms := string(data)
		if strings.Contains(ms, "core-api") || strings.Contains(ms, "postgres") {
			t.Fatal("mtls must not leak Core")
		}
	}
}
