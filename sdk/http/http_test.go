package httphelper

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// NewClient honors HTTP_PROXY: the request arrives at the proxy.
func TestNewClientUsesProxyFromEnvironment(t *testing.T) {
	var proxied bool
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied = true
		fmt.Fprint(w, "via-proxy")
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")
	client := NewClient()
	resp, err := client.Get(proxy.URL + "/x")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "via-proxy" || !proxied {
		t.Fatalf("body=%q proxied=%v, want via-proxy/true", body, proxied)
	}
}

// Default timeout is 30s and insecure skip is opt-in.
func TestNewClientDefaults(t *testing.T) {
	c := NewClient()
	if c.Timeout.Seconds() != 30 {
		t.Fatalf("timeout = %v, want 30s", c.Timeout)
	}
	tr, ok := c.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", c.Transport)
	}
	if tr.Proxy == nil {
		t.Fatal("transport Proxy must be set (ProxyFromEnvironment)")
	}
}
