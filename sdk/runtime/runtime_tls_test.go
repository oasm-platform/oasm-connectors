package runtime

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	pb "github.com/oasm-platform/oasm-connectors/sdk/proto/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// testCA is a throwaway CA used to mint test leaf certs. CA + leaf pairs are
// written as PEM files (the SDK consumes files via WORKER_TLS_*), so tests
// exercise the file-loading path end to end.
type testCA struct {
	t      *testing.T
	caFile string
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "oasm-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(2 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	writePEM(t, caFile, "CERTIFICATE", der)
	return &testCA{t: t, caFile: caFile, cert: tmpl, key: key}
}

// newLeaf mints a leaf cert signed by the CA. ips become IP SANs so the leaf
// can serve TLS for a dialed address (gRPC derives the server name from the
// target). client+server auth usages make one leaf usable on both ends.
func (c *testCA) newLeaf(commonName string, ips []net.IP) (certFile, keyFile string) {
	t := c.t
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatalf("create leaf cert: %v", err)
	}
	certFile = filepath.Join(t.TempDir(), "cert.pem")
	keyFile = filepath.Join(t.TempDir(), "key.pem")
	writePEM(t, certFile, "CERTIFICATE", der)
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal leaf key: %v", err)
	}
	writePEM(t, keyFile, "EC PRIVATE KEY", keyDER)
	return certFile, keyFile
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der}), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// startFakeServerTLS is startFakeServer over mutual TLS: the server presents
// certFile/keyFile and requires a client cert signed by the caFile CA.
func startFakeServerTLS(t *testing.T, srv pb.ConnectorServiceServer, caFile, certFile, keyFile string) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { lis.Close() })

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatalf("read ca: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("append ca: %v", err)
	}
	creds := credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	})
	gs := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterConnectorServiceServer(gs, srv)
	go gs.Serve(lis)
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

// testRunError runs Run and returns its error (or times out).
func testRunError(t *testing.T, rt *Runtime) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- rt.Run(ctx) }()
	select {
	case err := <-errCh:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s")
		return nil
	}
}

// TestRunAllTLSEnvDialsMTLSAndRegisters — with WORKER_TLS_CA, WORKER_TLS_CERT
// and WORKER_TLS_KEY all set, Run must dial over mTLS and register against a
// TLS worker. The server requires and verifies the client cert, so a plaintext
// dial (the pre-change behavior) cannot register here.
func TestRunAllTLSEnvDialsMTLSAndRegisters(t *testing.T) {
	pki := newTestCA(t)
	serverCert, serverKey := pki.newLeaf("worker", []net.IP{net.ParseIP("127.0.0.1")})
	clientCert, clientKey := pki.newLeaf("connector", nil)

	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("WORKER_TOKEN", "tok-mtls")
	t.Setenv("EXECUTION_ID", "exec-mtls")
	t.Setenv("JOB_ID", "job-mtls")
	t.Setenv("TOOL", "nuclei")
	t.Setenv("WORKER_TLS_CA", pki.caFile)
	t.Setenv("WORKER_TLS_CERT", clientCert)
	t.Setenv("WORKER_TLS_KEY", clientKey)

	srv := newFakeConnectorServer(nil)
	addr := startFakeServerTLS(t, srv, pki.caFile, serverCert, serverKey)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	rt := New(connector.New(&fakeAdapter{}))
	_, _ = runRuntime(t, rt)

	reg := waitRegister(t, srv)
	if reg.Token != "tok-mtls" {
		t.Errorf("Register.Token = %q, want tok-mtls", reg.Token)
	}
}

// TestRunMissingTLSVarFallsBackToPlaintext — when any of the three WORKER_TLS_*
// vars is unset, behavior must stay exactly as before: plaintext dial. Setting
// CA and CERT only (KEY empty) must still register against a plaintext server.
func TestRunMissingTLSVarFallsBackToPlaintext(t *testing.T) {
	pki := newTestCA(t)
	clientCert, _ := pki.newLeaf("connector", nil)

	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("WORKER_TOKEN", "tok-plain")
	t.Setenv("EXECUTION_ID", "exec-plain")
	t.Setenv("WORKER_TLS_CA", pki.caFile)
	t.Setenv("WORKER_TLS_CERT", clientCert)
	t.Setenv("WORKER_TLS_KEY", "") // missing → plaintext fallback

	srv := newFakeConnectorServer(nil)
	addr := startFakeServer(t, srv)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	rt := New(connector.New(&fakeAdapter{}))
	_, _ = runRuntime(t, rt)

	reg := waitRegister(t, srv)
	if reg.Token != "tok-plain" {
		t.Errorf("Register.Token = %q, want tok-plain", reg.Token)
	}
}

// TestRunMTLSWrongClientCertReturnsClearError — the connector cert is signed by
// a CA the worker does not trust; the handshake must fail and Run must surface
// a TLS error instead of hanging or silently falling back to plaintext.
func TestRunMTLSWrongClientCertReturnsClearError(t *testing.T) {
	workerPKI := newTestCA(t)
	roguePKI := newTestCA(t) // cert here is signed by an unknown CA
	serverCert, serverKey := workerPKI.newLeaf("worker", []net.IP{net.ParseIP("127.0.0.1")})
	clientCert, clientKey := roguePKI.newLeaf("connector", nil)

	t.Setenv("WORKER_GRPC_ADDR", "")
	t.Setenv("WORKER_TOKEN", "tok-badcert")
	t.Setenv("EXECUTION_ID", "exec-badcert")
	t.Setenv("WORKER_TLS_CA", workerPKI.caFile)
	t.Setenv("WORKER_TLS_CERT", clientCert)
	t.Setenv("WORKER_TLS_KEY", clientKey)

	srv := &fakeConnectorServer{registerCh: make(chan *pb.Register, 1)}
	addr := startFakeServerTLS(t, srv, workerPKI.caFile, serverCert, serverKey)
	t.Setenv("WORKER_GRPC_ADDR", addr)

	rt := New(connector.New(&fakeAdapter{}))
	err := testRunError(t, rt)
	if err == nil {
		t.Fatal("Run returned nil, want an mTLS handshake error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "tls") && !strings.Contains(msg, "handshake") {
		t.Errorf("Run error = %q, want it to mention the TLS handshake failure", msg)
	}

	select {
	case <-srv.registerCh:
		t.Fatal("server received Register; a rejected client cert must never register")
	default:
	}
}

// TestRunMTLSBadCAFileFailsFast — all three vars set but the CA file does not
// exist: Run must fail fast with a clear credentials error, before dialing.
func TestRunMTLSBadCAFileFailsFast(t *testing.T) {
	t.Setenv("WORKER_GRPC_ADDR", "localhost:1") // never dialed if creds load fails
	t.Setenv("WORKER_TOKEN", "tok-badca")
	t.Setenv("EXECUTION_ID", "exec-badca")
	t.Setenv("WORKER_TLS_CA", filepath.Join(t.TempDir(), "missing-ca.pem"))
	t.Setenv("WORKER_TLS_CERT", "x")
	t.Setenv("WORKER_TLS_KEY", "y")

	rt := New(connector.New(&fakeAdapter{}))
	err := testRunError(t, rt)
	if err == nil {
		t.Fatal("Run returned nil, want a credentials load error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "mTLS") || !strings.Contains(msg, "fatal") {
		t.Errorf("Run error = %q, want a fatal mTLS credentials error", msg)
	}
}
