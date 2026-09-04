package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
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
// When TemplateIds is set, only -id is emitted as a filter: -severity/-tags/-etags
// are dropped (with a warning) because mixing -id with template selection filters
// made nuclei silently match nothing and report zero findings. When no config is
// provided the manifest.yaml defaults apply: rateLimit=150, concurrency=25.
func buildArgs(target string, cfg Config) []string {
	var args []string

	// Stable flags first: -duc disables the update check (the container has no
	// network at runtime), -silent hides banner noise, -nc disables colored output.
	args = append(args, "-duc", "-silent", "-nc")

	if len(cfg.TemplateIds) > 0 {
		if len(cfg.Severity) > 0 || len(cfg.Tags) > 0 || len(cfg.ExcludeTags) > 0 {
			log.Printf("nuclei: templateIds set — dropping -severity/-tags/-etags (incompatible with -id)")
		}
		args = append(args, "-id", strings.Join(cfg.TemplateIds, ","))
	} else {
		if len(cfg.Severity) > 0 {
			args = append(args, "-severity", strings.Join(cfg.Severity, ","))
		}
		if len(cfg.Tags) > 0 {
			args = append(args, "-tags", strings.Join(cfg.Tags, ","))
		}
		if len(cfg.ExcludeTags) > 0 {
			args = append(args, "-etags", strings.Join(cfg.ExcludeTags, ","))
		}
	}

	// Manifest defaults apply when the config leaves them unset (manifest.yaml:
	// rateLimit default 150, concurrency default 25).
	rl := 150
	if cfg.RateLimit != nil {
		rl = *cfg.RateLimit
	}
	args = append(args, "-rl", strconv.Itoa(rl))

	c := 25
	if cfg.Concurrency != nil {
		c = *cfg.Concurrency
	}
	args = append(args, "-c", strconv.Itoa(c))

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
// error carrying the exit code and the tail of stderr. A malformed OASM_CONFIG
// fails the execution instead of silently falling back to defaults.
func (a *NucleiAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- []byte) error {
	target, _ := inputs["target"].(string)
	if target == "" {
		return fmt.Errorf("target required")
	}

	// Read optional OASM_CONFIG env — empty → zero Config (manifest defaults
	// apply); malformed → fail loudly instead of silently scanning with defaults.
	cfg, err := parseConfig(os.Getenv("OASM_CONFIG"))
	if err != nil {
		return fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}

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
	cmd.Stderr = &limitedWriter{buf: &stderrTail, limit: 32 * 1024}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", bin, err)
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024) // nuclei JSON lines can be large
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
		// Keep the Done.Error string compatible (contains `exit status N`) while
		// adding the numeric exit code for downstream consumers.
		code := -1
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		}
		return fmt.Errorf("nuclei exited: %w (exit code %d); stderr tail: %s", err, code, string(stderrTail))
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
