package main

import (
	"slices"
	"testing"
)

func TestZapProxyArgs(t *testing.T) {
	const k = "network.connection.httpProxy."
	got := zapProxyArgs("http://tok@worker:26277")
	want := []string{"-config", k + "enabled=true", "-config", k + "host=worker", "-config", k + "port=26277",
		"-config", k + "authEnabled=true", "-config", k + "username=tok", "-config", k + "password="}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	if zapProxyArgs("::bad") != nil {
		t.Fatal("unparseable proxy must yield no args")
	}
}
