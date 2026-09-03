package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// NucleiAdapter implements Validate/Execute for nuclei as a thin wrapper:
// receive input -> exec nuclei -> stream JSONL findings back through the SDK channel.
// Input validation is the worker node layer's responsibility, upstream of here.
type NucleiAdapter struct{}

// Config holds nuclei scan configuration parsed from the OASM_CONFIG env var.
// Fields map to nuclei CLI flags; pointers distinguish "absent" from zero-value.
type Config struct {
	Severity        []string `json:"severity"`
	Tags            []string `json:"tags"`
	ExcludeTags     []string `json:"excludeTags"`
	TemplateIds     []string `json:"templateIds"`
	RateLimit       *int     `json:"rateLimit"`
	Concurrency     *int     `json:"concurrency"`
	FollowRedirects *bool    `json:"followRedirects"`
}

// parseConfig unmarshals a JSON string into Config. An empty or malformed
// string returns a zero Config (no error for empty; error for malformed).
func parseConfig(raw string) (Config, error) {
	if strings.TrimSpace(raw) == "" {
		return Config{}, nil
	}
	var cfg Config
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// buildArgs maps a Config to nuclei CLI flags, always ending with -target and -jsonl.
func buildArgs(target string, cfg Config) []string {
	var args []string

	if len(cfg.Severity) > 0 {
		args = append(args, "-severity", strings.Join(cfg.Severity, ","))
	}
	if len(cfg.Tags) > 0 {
		args = append(args, "-tags", strings.Join(cfg.Tags, ","))
	}
	if len(cfg.ExcludeTags) > 0 {
		args = append(args, "-etags", strings.Join(cfg.ExcludeTags, ","))
	}
	if len(cfg.TemplateIds) > 0 {
		args = append(args, "-id", strings.Join(cfg.TemplateIds, ","))
	}
	if cfg.RateLimit != nil {
		args = append(args, "-rl", strconv.Itoa(*cfg.RateLimit))
	}
	if cfg.Concurrency != nil {
		args = append(args, "-c", strconv.Itoa(*cfg.Concurrency))
	}
	if cfg.FollowRedirects != nil && *cfg.FollowRedirects {
		args = append(args, "-follow-redirects")
	}

	args = append(args, "-target", target, "-jsonl")
	return args
}

// redactedArgs returns a copy of args with the value following -target
// replaced by [redacted] so scan targets are not leaked into logs.
func redactedArgs(args []string) []string {
	redacted := make([]string, len(args))
	copy(redacted, args)
	for i, a := range redacted {
		if a == "-target" && i+1 < len(redacted) {
			redacted[i+1] = "[redacted]"
		}
	}
	return redacted
}

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

	// Read optional OASM_CONFIG env — empty/invalid → zero Config (nuclei defaults).
	cfg, _ := parseConfig(os.Getenv("OASM_CONFIG"))

	bin := os.Getenv("NUCLEI_BIN")
	if bin == "" {
		bin = "nuclei"
	}
	args := buildArgs(target, cfg)
	log.Printf("nuclei: bin=%s args=%v", bin, redactedArgs(args))
	cmd := exec.CommandContext(ctx, bin, args...)
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
	findings, skipped := 0, 0
	done := func() {
		log.Printf("nuclei: done findings=%d skipped=%d", findings, skipped)
	}
	defer done()
	for scanner.Scan() {
		line := scanner.Bytes()
		var v map[string]any
		if json.Unmarshal(line, &v) != nil {
			skipped++ // banner/noise lines
			continue
		}
		out <- append([]byte(nil), line...)
		findings++
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
