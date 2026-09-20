package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// AcunetixAdapter implements Validate/Execute for the Acunetix scanner:
// resolve target -> find-or-create -> schedule scan -> poll to completion ->
// resolve the result id -> stream findings -> cleanup. Configuration comes from
// the per-job OASM_CONFIG profile (ACUNETIX_* env vars are the legacy fallback).
type AcunetixAdapter struct{}

// pollInterval is the delay between scan status polls. Production default is
// 15s; tests may shorten it.
var pollInterval = 15 * time.Second

// Validate is intentionally a no-op: inputs are validated upstream by the
// worker node against the connector's inputsSchema.
func (a *AcunetixAdapter) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

// Execute runs an Acunetix scan against target and streams every finding to
// out. Findings are collected BEFORE any cleanup; on any failure nothing is
// deleted (retention-on-failure). A target the connector created is deleted
// with its scans (the delete cascades); a reused target is never deleted.
func (a *AcunetixAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	raw, _ := inputs["target"].(string)
	if strings.TrimSpace(raw) == "" {
		return fmt.Errorf("target required")
	}
	address := canonicalTarget(raw)

	cfg, err := loadAcunetixConfig()
	if err != nil {
		return err
	}

	client := newAcunetixClient(cfg)

	targetID, found, err := client.findTargetByAddress(ctx, address)
	if err != nil {
		return fmt.Errorf("acunetix: find target: %w", err)
	}
	// created is true ONLY after a successful createTarget: a found/reused
	// target must never be deleted.
	created := false
	if !found {
		targetID, err = client.createTarget(ctx, address, cfg.TargetDescription, cfg.Criticality)
		if err != nil {
			return fmt.Errorf("acunetix: create target: %w", err)
		}
		created = true
	}

	scanID, err := client.createScan(ctx, targetID, cfg.ProfileID, cfg.MaxScanTime)
	if err != nil {
		return fmt.Errorf("acunetix: create scan: %w", err)
	}

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var s *scanItemResponse
poll:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s, err = client.getScan(ctx, scanID)
			if err != nil {
				return fmt.Errorf("acunetix: scan %s status: %w", scanID, err)
			}
			if s.CurrentSession == nil {
				continue // never deref nil
			}
			switch s.CurrentSession.Status {
			case "completed":
				break poll
			case "aborted", "failed":
				return fmt.Errorf("acunetix: scan %s ended with status %s", scanID, s.CurrentSession.Status)
			default:
				// scheduled, queued, starting, processing, aborting, pausing,
				// paused, unknown/future → keep polling (bounded by ctx).
			}
		}
	}

	if s == nil || s.CurrentSession == nil {
		return fmt.Errorf("acunetix: scan %s completed without a scan session", scanID)
	}

	resultID, err := resolveResultID(ctx, client, scanID, s.CurrentSession.ScanSessionID)
	if err != nil {
		return err
	}

	if err := collectFindings(ctx, client, scanID, resultID, address, out); err != nil {
		return err
	}

	// ponytail: best-effort cleanup AFTER a successful collect only. A created
	// target is deleted (cascading its scan); a reused target is never touched,
	// so its scan is deleted instead. Created targets orphaned by a mid-flow
	// failure accumulate by design (retention-on-failure) and are marked by the
	// default `oasm-scan` description for later operator reaping.
	if created {
		if err := client.deleteTarget(ctx, targetID); err != nil {
			log.Printf("acunetix: cleanup delete target %s failed: %v", targetID, err)
		}
	} else {
		if err := client.deleteScan(ctx, scanID); err != nil {
			log.Printf("acunetix: cleanup delete scan %s failed: %v", scanID, err)
		}
	}

	return nil
}

// resolveResultID picks the scan result to collect findings from. An empty
// result list is a hard error — there is no silent 0-finding path.
func resolveResultID(ctx context.Context, c *acunetixClient, scanID, sessionID string) (string, error) {
	results, err := c.getScanResults(ctx, scanID)
	if err != nil {
		return "", err
	}
	if len(results) == 0 {
		return "", fmt.Errorf("acunetix: scan %s has no results", scanID)
	}
	// Cross-reference: Acunetix's result_id and current_session.scan_session_id
	// are distinct fields in the spec (doc:5907-5910 vs doc:4192-4194) but the
	// same identifier in practice; equality is a cross-reference, never an
	// assumption.
	if sessionID != "" {
		for _, r := range results {
			if r.ResultID == sessionID {
				return r.ResultID, nil
			}
		}
	}
	if len(results) == 1 {
		return results[0].ResultID, nil
	}
	// Fallback: newest start_date, parsed as RFC3339 when possible.
	best := results[0]
	bestT, bestOK := parseStartDate(best.StartDate)
	for _, r := range results[1:] {
		rt, ok := parseStartDate(r.StartDate)
		newer := (ok && bestOK && rt.After(bestT)) || (!bestOK && ok)
		if newer || (!bestOK && !ok && r.StartDate > best.StartDate) {
			best, bestT, bestOK = r, rt, ok
		}
	}
	return best.ResultID, nil
}

// parseStartDate parses a scan-result start_date, reporting whether it was
// parseable. Callers fall back to a lexical comparison when both dates are
// unparseable.
func parseStartDate(raw string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts, true
		}
	}
	return time.Time{}, false
}
