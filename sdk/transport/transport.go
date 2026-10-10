// Package transport dials the Worker gRPC endpoint, plaintext or mTLS.
package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Dial creates a lazy gRPC ClientConn to the Worker. nil creds means
// plaintext (the Worker falls back to it when WORKER_TLS_* is unset).
func Dial(target string, creds credentials.TransportCredentials) (*grpc.ClientConn, error) {
	if target == "" {
		return nil, fmt.Errorf("target required")
	}
	if creds == nil {
		creds = insecure.NewCredentials()
	}
	return grpc.NewClient(target, grpc.WithTransportCredentials(creds))
}

// LoadMTLS builds mTLS credentials for connector -> Worker: caFile verifies
// the Worker, certFile/keyFile is the connector client cert. An empty
// serverName lets gRPC derive it from the dial address.
func LoadMTLS(caFile, certFile, keyFile, serverName string) (credentials.TransportCredentials, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read ca file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("failed to append CA cert")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load key pair: %w", err)
	}
	return credentials.NewTLS(&tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}), nil
}
