package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeGMP is an in-process GMP-over-TLS server for tests. It generates a
// self-signed certificate at test time, listens on 127.0.0.1:0, reads one
// request per line, and writes a scripted XML response.
type fakeGMP struct {
	t    *testing.T
	ln   net.Listener
	port int

	mu        sync.Mutex
	reqs      []string
	onRequest func(req string) (string, error)
}

// newFakeGMP starts the fake server and registers cleanup.
func newFakeGMP(t *testing.T) *fakeGMP {
	t.Helper()
	cert, err := generateSelfSignedCert()
	if err != nil {
		t.Fatalf("generate cert: %v", err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split addr: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	f := &fakeGMP{t: t, ln: ln, port: port}
	go f.acceptLoop()
	t.Cleanup(f.Close)
	return f
}

// config returns a client config pointed at the fake server, skipping TLS
// verification (the cert is self-signed and generated per test).
func (f *fakeGMP) config() *openvasConfig {
	return &openvasConfig{Host: "127.0.0.1", Port: f.port, DisableTLSChecks: true}
}

// script replies with each response in order, one per request line. Requests
// beyond the script are answered with nothing.
func (f *fakeGMP) script(responses ...string) {
	var (
		mu sync.Mutex
		i  int
	)
	f.onRequest = func(string) (string, error) {
		mu.Lock()
		defer mu.Unlock()
		if i >= len(responses) {
			return "", nil
		}
		r := responses[i]
		i++
		return r, nil
	}
}

// setHandler installs an arbitrary per-request handler.
func (f *fakeGMP) setHandler(h func(req string) (string, error)) {
	f.onRequest = h
}

// requests returns the request lines received so far.
func (f *fakeGMP) requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.reqs...)
}

// Close stops the listener.
func (f *fakeGMP) Close() { _ = f.ln.Close() }

func (f *fakeGMP) acceptLoop() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.serve(conn)
	}
}

func (f *fakeGMP) serve(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		req := strings.TrimRight(line, "\r\n")

		f.mu.Lock()
		f.reqs = append(f.reqs, req)
		handler := f.onRequest
		f.mu.Unlock()

		if handler == nil {
			continue
		}
		reply, herr := handler(req)
		if reply != "" {
			if _, err := w.WriteString(reply); err != nil {
				return
			}
			if err := w.Flush(); err != nil {
				return
			}
		}
		if herr != nil {
			return
		}
	}
}

// generateSelfSignedCert builds a throwaway ECDSA server certificate valid for
// 127.0.0.1/localhost. The client uses DisableTLSChecks, so trust is not
// exercised here; the cert only enables a real TLS handshake.
func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "openvas-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}
