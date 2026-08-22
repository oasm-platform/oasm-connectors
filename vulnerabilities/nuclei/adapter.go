package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
)

// NucleiAdapter implements Validate/Execute for nuclei as a thin wrapper:
// receive input -> exec nuclei -> stream JSONL findings back through the SDK channel.
// Input validation is the worker node layer's responsibility, upstream of here.
type NucleiAdapter struct{}

// Validate is intentionally a no-op: inputs are validated upstream by the
// worker node against the connector's inputsSchema.
func (a *NucleiAdapter) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

// Execute runs nuclei against target and streams every JSONL finding to out.
// Non-JSON stdout lines (banner/noise) are skipped. Non-zero exit returns an
// error carrying the tail of stderr.
func (a *NucleiAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- []byte) error {
	target, _ := inputs["target"].(string)
	if target == "" {
		return fmt.Errorf("target required")
	}
	bin := os.Getenv("NUCLEI_BIN")
	if bin == "" {
		bin = "nuclei"
	}
	cmd := exec.CommandContext(ctx, bin, "-target", target, "-jsonl")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}
	var stderrTail []byte
	cmd.Stderr = &limitedWriter{buf: &stderrTail, limit: 2048}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", bin, err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024) // nuclei JSON lines can be large
	for scanner.Scan() {
		line := scanner.Bytes()
		var v map[string]any
		if json.Unmarshal(line, &v) != nil {
			continue // skip banner/noise lines
		}
		out <- append([]byte(nil), line...)
	}
	if err := scanner.Err(); err != nil {
		_ = cmd.Wait()
		return fmt.Errorf("read stdout: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("nuclei exited: %w; stderr tail: %s", err, string(stderrTail))
	}
	return nil
}

// limitedWriter keeps only the last `limit` bytes written to it.
type limitedWriter struct {
	buf   *[]byte
	limit int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	*w.buf = append(*w.buf, p...)
	if len(*w.buf) > w.limit {
		*w.buf = (*w.buf)[len(*w.buf)-w.limit:]
	}
	return len(p), nil
}
