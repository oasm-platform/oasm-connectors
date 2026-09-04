package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/tencat-dev/nessus-client-go/nessus"
)

// NessusAdapter implements Validate/Execute for the Nessus scanner:
// receive input -> authenticate -> create+launch scan -> poll to completion ->
// stream findings -> cleanup. Configuration comes from the per-job OASM_CONFIG
// profile (NESSUS_* env vars are the legacy fallback).
type NessusAdapter struct{}

// pollInterval is the delay between scan status polls. Production default is
// 15s; tests may shorten it.
var pollInterval = 15 * time.Second

// Validate is intentionally a no-op: inputs are validated upstream by the
// worker node against the connector's inputsSchema.
func (a *NessusAdapter) Validate(_ context.Context, _ map[string]any) error {
	return nil
}

// Execute runs a Nessus scan against target and streams every finding to
// out. The scan is deleted only after findings streamed successfully
// (retention-on-failure).
func (a *NessusAdapter) Execute(ctx context.Context, inputs map[string]any, out chan<- connector.Finding) error {
	target, _ := inputs["target"].(string)
	target = strings.TrimSpace(target)
	if target == "" {
		return fmt.Errorf("target required")
	}

	cfg, err := loadNessusConfig()
	if err != nil {
		return err
	}

	client, err := newNessusClient(cfg)
	if err != nil {
		return err
	}

	// Per-execution scan name: EXECUTION_ID is set only at container start, so
	// it is stale on warm-pool reuse. The target is per-execution; a timestamp
	// suffix keeps reused scans distinguishable in the Nessus UI.
	name := fmt.Sprintf("%s %s", target, time.Now().UTC().Format("20060102T150405Z"))

	tmpl := nessus.TemplateBasic
	if cfg.TemplateUUID != "" {
		tmpl = nessus.TemplateType(cfg.TemplateUUID)
	}

	resp, err := client.ScansCreate(&nessus.ScansCreateRequest{
		TemplateUUID: tmpl,
		Settings: &nessus.ScansCreateSetting{
			Name:        name,
			Enabled:     false,
			LaunchNow:   true,
			TextTargets: target,
			FolderID:    cfg.FolderID,
			PolicyID:    cfg.PolicyID,
		},
	})
	if err != nil {
		return fmt.Errorf("nessus: create scan: %w", err)
	}
	if resp.Scan == nil {
		return fmt.Errorf("nessus: create scan returned no scan")
	}
	scanID := resp.Scan.ID

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	var details *nessus.ScansDetailsResponse
poll:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			d, err := client.ScansDetails(scanID, &nessus.ScansDetailsQuery{})
			if err != nil {
				return fmt.Errorf("nessus: scan %d details: %w", scanID, err)
			}
			if d.Info == nil {
				return fmt.Errorf("nessus: scan %d details missing info", scanID)
			}
			switch d.Info.Status {
			case nessus.ScanCompleted:
				details = d
				break poll
			case nessus.ScanAborted, nessus.TypeCanceled, nessus.ScanEmpty, nessus.TypeStopping:
				return fmt.Errorf("scan %d ended with status %s", scanID, d.Info.Status)
			default:
				// still running; keep polling
			}
		}
	}

	if err := collectFindings(ctx, client, details, target, out); err != nil {
		return err
	}

	if err := client.ScansDelete(scanID); err != nil {
		log.Printf("nessus: cleanup delete failed scan=%d: %v", scanID, err)
	}

	return nil
}
