package env

import (
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

// Load reads Worker-injected env vars. Returns error if WORKER_GRPC_ADDR is missing.
func Load() (*Config, error) {
	addr := os.Getenv("WORKER_GRPC_ADDR")
	if addr == "" {
		return nil, fmt.Errorf("WORKER_GRPC_ADDR not set")
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
