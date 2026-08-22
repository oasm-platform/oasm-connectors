package transport

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// DefaultWorkerAddr is the default Worker gRPC endpoint.
const DefaultWorkerAddr = "localhost:50051"

// DialOpts controls how Dial connects to Worker.
// ponytail: minimal surface — only Insecure toggle; mTLS creds come from LoadMTLS/BuildTLSConfig.
type DialOpts struct {
	Insecure bool
}

// Dial creates a lazy gRPC ClientConn to the Worker endpoint.
// Target is required; empty target returns an error.
// ponytail: no streaming/multiplex here — just the hidden dial; caller never touches grpc directly.
func Dial(target string, opts DialOpts) (*grpc.ClientConn, error) {
	if target == "" {
		return nil, fmt.Errorf("target required")
	}
	_ = opts
	cred := insecure.NewCredentials()
	return grpc.NewClient(target, grpc.WithTransportCredentials(cred))
}

// DialWithTLSCreds dials Worker with explicit TransportCredentials (mTLS).
func DialWithTLSCreds(target string, creds credentials.TransportCredentials) (*grpc.ClientConn, error) {
	if target == "" {
		return nil, fmt.Errorf("target required")
	}
	if creds == nil {
		return nil, fmt.Errorf("credentials required")
	}
	return grpc.NewClient(target, grpc.WithTransportCredentials(creds))
}

// Connect dials Worker with insecure fallback and mTLS-ready signature.
// If target is empty, DefaultWorkerAddr is used. Context is currently unused
// (lazy dial) but kept for API compatibility and future dial-blocking.
// ponytail: ceiling is lazy insecure dial; blocking dial + TLS switch via DialWithTLSCreds.
func Connect(ctx context.Context, target string) (*grpc.ClientConn, error) {
	_ = ctx
	if target == "" {
		target = DefaultWorkerAddr
	}
	return Dial(target, DialOpts{Insecure: true})
}
