package transport

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

// LoadMTLS builds mTLS TransportCredentials for connector -> Worker.
// caFile is the CA cert to verify the Worker; certFile/keyFile is the connector client cert.
// ponytail: minimal — file-based only; rotation hook will be added with lifecycle if needed.
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
	cfg := &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}
	return credentials.NewTLS(cfg), nil
}

// LoadTLSCredentials is an alias for LoadMTLS kept for spec compatibility.
func LoadTLSCredentials(caFile, certFile, keyFile, serverName string) (credentials.TransportCredentials, error) {
	return LoadMTLS(caFile, certFile, keyFile, serverName)
}

// BuildTLSConfig builds a *tls.Config for mTLS without wrapping as grpc credentials.
func BuildTLSConfig(caFile, certFile, keyFile, serverName string) (*tls.Config, error) {
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
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{cert},
		ServerName:   serverName,
		MinVersion:   tls.VersionTLS12,
	}, nil
}
