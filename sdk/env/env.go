package env

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Config holds Worker-injected connection parameters.
type Config struct {
	WorkerAddr  string // WORKER_GRPC_ADDR
	Token       string // WORKER_TOKEN
	ExecutionID string // EXECUTION_ID
	JobID       string // JOB_ID
	Tool        string // TOOL
	TraceID     string // TRACE_ID
}

var (
	// ErrWorkerAddrMissing is returned when WORKER_GRPC_ADDR is unset.
	// The worker always injects WORKER_GRPC_ADDR into connector containers,
	// so Run treats a missing addr as a fatal misconfiguration and fails fast.
	ErrWorkerAddrMissing = errors.New("WORKER_GRPC_ADDR not set")

	// ErrExecutionIDMissing is returned when EXECUTION_ID is unset and the
	// OASM_ALLOW_LEGACY_NO_EXEC_ID opt-out is not set. The worker routes
	// ExecuteJob by execution identity, so without it the connector would
	// register and then wait forever — it must fail fast instead.
	ErrExecutionIDMissing = errors.New("EXECUTION_ID not set")
)

// Load reads Worker-injected env vars. Returns an error when
// WORKER_GRPC_ADDR is missing, or when EXECUTION_ID is missing unless
// OASM_ALLOW_LEGACY_NO_EXEC_ID is set (legacy connectors without an
// execution identity keep the no-ExecuteJob behavior).
func Load() (*Config, error) {
	addr := os.Getenv("WORKER_GRPC_ADDR")
	if addr == "" {
		return nil, ErrWorkerAddrMissing
	}
	if os.Getenv("EXECUTION_ID") == "" && os.Getenv("OASM_ALLOW_LEGACY_NO_EXEC_ID") == "" {
		return nil, fmt.Errorf("%w: worker routes ExecuteJob by execution identity; set OASM_ALLOW_LEGACY_NO_EXEC_ID=1 to keep legacy (no-ExecuteJob) behavior", ErrExecutionIDMissing)
	}
	return &Config{
		WorkerAddr:  addr,
		Token:       os.Getenv("WORKER_TOKEN"),
		ExecutionID: os.Getenv("EXECUTION_ID"),
		JobID:       os.Getenv("JOB_ID"),
		Tool:        os.Getenv("TOOL"),
		TraceID:     os.Getenv("TRACE_ID"),
	}, nil
}

// TLSFiles returns the Worker mTLS file paths from WORKER_TLS_CA,
// WORKER_TLS_CERT and WORKER_TLS_KEY. The boolean is false when any of the
// three is unset — the caller then falls back to plaintext, keeping Load's
// contract unchanged.
func TLSFiles() (ca, cert, key string, ok bool) {
	ca = os.Getenv("WORKER_TLS_CA")
	cert = os.Getenv("WORKER_TLS_CERT")
	key = os.Getenv("WORKER_TLS_KEY")
	return ca, cert, key, ca != "" && cert != "" && key != ""
}

// LoadInputs reads all INPUT_* env vars and returns them as a map.
// Keys are lowercased: INPUT_TARGET → "target", INPUT_SOME_KEY → "some_key".
func LoadInputs() map[string]any {
	inputs := make(map[string]any)
	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "INPUT_") {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				key := strings.ToLower(strings.TrimPrefix(parts[0], "INPUT_"))
				inputs[key] = parts[1]
			}
		}
	}
	return inputs
}
