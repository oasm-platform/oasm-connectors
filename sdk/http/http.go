// Package httphelper is the shared proxy-aware HTTP client constructor for
// connectors: every API client must route through ProxyFromEnvironment so
// worker-injected HTTP_PROXY/HTTPS_PROXY/ALL_PROXY (the worker-local egress
// proxy) are honored instead of bypassed by bespoke transports.
package httphelper

import (
	"crypto/tls"
	"net/http"
	"time"
)

// Options tunes the shared client. Zero value = 30s timeout, verified TLS.
type Options struct {
	Timeout            time.Duration
	InsecureSkipVerify bool
}

// Option overrides one Options field.
type Option func(*Options)

// WithTimeout sets the client timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) { o.Timeout = d }
}

// WithInsecureSkipVerify keeps a self-signed/on-prem TLS behavior
// (e.g. on-prem Nessus/Acunetix); default verifies.
func WithInsecureSkipVerify(skip bool) Option {
	return func(o *Options) { o.InsecureSkipVerify = skip }
}

// NewClient builds an *http.Client that honors the standard proxy
// environment (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY + NO_PROXY) via
// http.ProxyFromEnvironment — the mechanism the worker egress proxy relies
// on. Per-tool TLS knobs stay opt-in through Options.
func NewClient(opts ...Option) *http.Client {
	o := Options{Timeout: 30 * time.Second}
	for _, fn := range opts {
		fn(&o)
	}
	return &http.Client{
		Timeout: o.Timeout,
		Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: o.InsecureSkipVerify},
		},
	}
}
