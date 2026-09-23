package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// OpenVASAdapter drives a Greenbone/OpenVAS gvmd instance over GMP:
// connect -> authenticate -> create target -> create task -> start task ->
// poll to Done -> stream findings -> cleanup. Configuration comes from the
// per-job OASM_CONFIG profile (OPENVAS_* env vars are the legacy fallback).
type OpenVASAdapter struct{}

// pollInterval is the delay between task status polls. Production default is
// 15s; tests may shorten it.
var pollInterval = 15 * time.Second

// Validate is intentionally a no-op: inputs are validated upstream by the
// worker node against the connector's inputsSchema.
func (a *OpenVASAdapter) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

// taskName builds the per-execution task name. EXECUTION_ID is set only at
// container start, so it is stale on warm-pool reuse; the target plus a
// timestamp keep reused scans distinguishable.
func taskName(target string) string {
	return fmt.Sprintf("oasm-%s-%s", target, time.Now().UTC().Format("20060102T150405Z"))
}

// Execute runs a scan against target and streams every finding to out.
//
// Error-prefix ownership (README): loadOpenVASConfig errors are unprefixed
// and wrapped fatal: here; dial/send/command errors already carry exactly
// one fatal:/retryable: prefix and are returned AS-IS; this function's own
// literals carry their prefix directly.
//
// Cleanup: exactly ONE cancel-cleanup defer. On ctx cancellation the
// container is torn down, so nothing later would run — a detached context
// stops and deletes the task and deletes the connector-created target.
// Any other failure retains everything (retention-on-failure). The success
// path deletes the task and target after findings stream. out is never
// closed; the runtime owns the channel.
func (a *OpenVASAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	target, _ := inputs["target"].(string)
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("fatal: target required")
	}

	cfg, err := loadOpenVASConfig()
	if err != nil {
		return fmt.Errorf("fatal: %w", err)
	}

	c, err := dialGMP(ctx, cfg)
	if err != nil {
		return err
	}
	defer c.Close()

	if err := c.authenticate(ctx, cfg.Username, cfg.Password); err != nil {
		return err
	}

	// Declared before the cancel-cleanup defer so its closure can capture
	// them (a closure cannot capture a variable first declared later).
	var taskID string
	var started bool
	createdTarget := false

	// The "oasm-" name marks connector-created orphans for operator reaping.
	targetID, err := c.CreateTarget(ctx, taskName(target), target, cfg.PortListID)
	if err != nil {
		return err
	}
	createdTarget = true

	// The ONE cleanup defer: does work only when ctx was cancelled. Ordinary
	// failures keep the task/target for debugging (retention-on-failure).
	defer func() {
		if ctx.Err() == nil {
			return
		}
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if started {
			if err := c.StopTask(cctx, taskID); err != nil {
				log.Printf("openvas: cleanup stop task %s failed: %v", taskID, err)
			}
		}
		if taskID != "" {
			if err := c.DeleteTask(cctx, taskID); err != nil {
				log.Printf("openvas: cleanup delete task %s failed: %v", taskID, err)
			}
		}
		if createdTarget {
			if err := c.DeleteTarget(cctx, targetID); err != nil {
				log.Printf("openvas: cleanup delete target %s failed: %v", targetID, err)
			}
		}
	}()

	// Plain `=`: taskID was pre-declared above and err already exists.
	taskID, err = c.CreateTask(ctx, taskName(target), cfg.ConfigID, targetID, cfg.ScannerID)
	if err != nil {
		return err // target retained (retention-on-failure)
	}

	reportID, err := c.StartTask(ctx, taskID)
	started = true
	if err != nil {
		return err
	}
	log.Printf("openvas: task started task=%s report=%s", taskID, reportID)

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
poll:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			status, err := c.GetTaskStatus(ctx, taskID)
			if err != nil {
				return err
			}
			switch status {
			case taskStatusDone:
				break poll
			case taskStatusInterrupted:
				// Server-side/transient — a re-scan may succeed.
				return fmt.Errorf("retryable: openvas: task %s was interrupted", taskID)
			case taskStatusStopped, taskStatusDeleteRequested:
				// Administrative — retrying cannot help.
				return fmt.Errorf("fatal: openvas: task %s ended with status %s", taskID, status)
			default:
				// New/Requested/Processing/Running/Stop Requested and any
				// future value: keep polling (bounded by ctx).
			}
		}
	}

	if err := collectFindings(ctx, c, taskID, target, out); err != nil {
		return err
	}

	// Success-path cleanup: best effort, logged, never fatal — findings
	// already streamed. The target is the one this connector created above.
	if err := c.DeleteTask(ctx, taskID); err != nil {
		log.Printf("openvas: cleanup delete task %s failed: %v", taskID, err)
	}
	if err := c.DeleteTarget(ctx, targetID); err != nil {
		log.Printf("openvas: cleanup delete target %s failed: %v", targetID, err)
	}
	return nil
}
