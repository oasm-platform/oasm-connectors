package main

import (
	"slices"
	"testing"
)

// Proxy userinfo moves to PROXYUSER/PROXYPASS; -useproxy gets a bare URL.
func TestNiktoProxyArgs(t *testing.T) {
	got := niktoProxyArgs("http://tok@worker:26277")
	want := []string{"-useproxy", "http://worker:26277", "-Option", "PROXYUSER=tok", "-Option", "PROXYPASS="}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got := niktoProxyArgs("http://worker:26277"); !slices.Equal(got, []string{"-useproxy", "http://worker:26277"}) {
		t.Fatalf("no auth: got %v", got)
	}
}
