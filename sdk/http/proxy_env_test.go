package httphelper

import "testing"

func TestProxyOrEnv(t *testing.T) {
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(k, "")
	}
	if got := ProxyOrEnv(""); got != "" {
		t.Fatalf("no env: got %q", got)
	}
	t.Setenv("HTTP_PROXY", "http://tok@worker:26277")
	if got := ProxyOrEnv(""); got != "http://tok@worker:26277" {
		t.Fatalf("env: got %q", got)
	}
	if got := ProxyOrEnv("http://custom:8080"); got != "http://custom:8080" {
		t.Fatalf("configured must win, got %q", got)
	}
}
