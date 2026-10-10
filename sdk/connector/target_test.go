package connector

import (
	"strings"
	"testing"
)

func TestHostOnly(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com/a/b?x=1", "example.com"},
		{"example.com:443/x", "example.com"},
		{"   ", ""},
		{"http://EXAMPLE.com:8080", "EXAMPLE.com"},
		{"example.com", "example.com"},
		// userinfo and IPv6 literals must not be truncated at the first colon
		{"http://user:pw@example.com/x", "example.com"},
		{"https://[2001:db8::1]:8443/x", "2001:db8::1"},
		{"[::1]:8080", "::1"},
	}
	for _, tc := range cases {
		if got := HostOnly(tc.in); got != tc.want {
			t.Errorf("HostOnly(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestWebURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"example.com", "https://example.com"},
		{"https://example.com", "https://example.com"},
		{"http://example.com", "http://example.com"},
		{"example.com:8443", "https://example.com:8443"},
		{"https://example.com:8443/app", "https://example.com:8443/app"},
		{"http://a.example/x?y=1", "http://a.example/x?y=1"},
		{"  example.com  ", "https://example.com"},
		{"", ""},
		{"   ", ""},
	}
	for _, tc := range cases {
		if got := WebURL(tc.in); got != tc.want {
			t.Errorf("WebURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHostOf(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com:8443/app", "example.com:8443"},
		{"http://example.com", "example.com"},
		{"not a url", "not a url"},
	}
	for _, tc := range cases {
		if got := HostOf(tc.in); got != tc.want {
			t.Errorf("HostOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSingleHost(t *testing.T) {
	cases := []struct{ in, want, wantErr string }{
		{in: "example.com", want: "example.com"},
		{in: " 203.0.113.10 ", want: "203.0.113.10"},
		{in: "[2001:db8::1]", want: "[2001:db8::1]"},
		{in: "https://example.com/a/b?x=1", want: "example.com"},
		{in: "http://user:pw@example.com:8080/x", want: "example.com"},
		{in: "example.com:80", want: "example.com"},
		{in: "10.0.0.0/24", wantErr: "invalid target"},
		{in: "https://10.0.0.0/24", wantErr: "invalid target"},
		{in: "example.com:80-90", wantErr: "invalid target"},
		{in: "a.com,b.com", wantErr: "invalid target"},
		{in: "*.example.com", wantErr: "invalid target"},
		{in: "", wantErr: "target required"},
	}
	for _, c := range cases {
		got, err := SingleHost(map[string]any{"target": c.in})
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("SingleHost(%q) error = %v, want %q", c.in, err, c.wantErr)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("SingleHost(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

func TestResolveIPv4Literal(t *testing.T) {
	if got := ResolveIPv4("203.0.113.10"); got != "203.0.113.10" {
		t.Fatalf("ResolveIPv4 literal = %q", got)
	}
	if got := ResolveIPv4("localhost"); got != "127.0.0.1" {
		t.Fatalf("ResolveIPv4(localhost) = %q, want 127.0.0.1", got)
	}
}
