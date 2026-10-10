package transport

import "testing"

func TestDialPlaintextIsLazy(t *testing.T) {
	c, err := Dial("localhost:0", nil)
	if err != nil {
		t.Fatalf("expected lazy dial to succeed, got %v", err)
	}
	_ = c.Close()
}

func TestDialRequiresTarget(t *testing.T) {
	if _, err := Dial("", nil); err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestLoadMTLSMissingCAFails(t *testing.T) {
	if _, err := LoadMTLS("does-not-exist.pem", "c", "k", ""); err == nil {
		t.Fatal("expected error for missing CA file")
	}
}
