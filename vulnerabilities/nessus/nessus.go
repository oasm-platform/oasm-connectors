package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/tencat-dev/nessus-client-go/nessus"
)

// nessusConfig holds the Nessus connection + scan settings.
type nessusConfig struct {
	URL          string
	AccessKey    string
	SecretKey    string
	TemplateUUID string
	PolicyID     string
	FolderID     string
}

// configProfile is the OASM_CONFIG JSON shape the Worker ships per job.
// Keys are camelCase to mirror manifest.yaml configSchema.
type configProfile struct {
	URL          string `json:"url"`
	AccessKey    string `json:"accessKey"`
	SecretKey    string `json:"secretKey"`
	TemplateUUID string `json:"templateUuid"`
	PolicyID     string `json:"policyId"`
	FolderID     string `json:"folderId"`
}

// loadNessusConfig reads the Nessus connection + scan settings. The primary
// source is OASM_CONFIG (the per-job config profile) — the SDK runtime
// overrides that env var per execution so a warm-pool reused container sees
// its own job's config rather than its first-run env. NESSUS_* env vars remain
// as a legacy fallback for direct-runtime use. URL, access key and secret key
// are required; the rest fall back to sane defaults.
func loadNessusConfig() (*nessusConfig, error) {
	cfg := &nessusConfig{}

	if raw := strings.TrimSpace(os.Getenv("OASM_CONFIG")); raw != "" {
		var p configProfile
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
		}
		cfg.URL = p.URL
		cfg.AccessKey = p.AccessKey
		cfg.SecretKey = p.SecretKey
		cfg.TemplateUUID = p.TemplateUUID
		cfg.PolicyID = p.PolicyID
		cfg.FolderID = p.FolderID
	} else {
		cfg.URL = os.Getenv("NESSUS_URL")
		cfg.AccessKey = os.Getenv("NESSUS_ACCESS_KEY")
		cfg.SecretKey = os.Getenv("NESSUS_SECRET_KEY")
		cfg.TemplateUUID = os.Getenv("NESSUS_TEMPLATE_UUID")
		cfg.PolicyID = os.Getenv("NESSUS_POLICY_ID")
		cfg.FolderID = os.Getenv("NESSUS_FOLDER_ID")
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("nessus URL required (config.url or NESSUS_URL)")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("nessus access key and secret key required (config.accessKey/secretKey or NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY)")
	}

	return cfg, nil
}

// newNessusClient builds a client that authenticates every request with the
// API access/secret key pair (X-ApiKeys header), then gates on
// ServerStatus()=="ready" before returning it.
func newNessusClient(cfg *nessusConfig) (*nessus.Client, error) {
	client, err := nessus.NewClient(
		nessus.WithAPIURL(cfg.URL),
		nessus.WithAPIKey(cfg.AccessKey, cfg.SecretKey),
	)
	if err != nil {
		return nil, fmt.Errorf("nessus: create client: %w", err)
	}

	st, err := client.ServerStatus()
	if err != nil {
		return nil, fmt.Errorf("nessus: server status: %w", err)
	}
	if st.Status != "ready" {
		return nil, fmt.Errorf("nessus: server not ready: status=%q", st.Status)
	}

	if cfg.FolderID == "" {
		if err := resolveScanFolder(client, cfg); err != nil {
			return nil, err
		}
	}

	return client, nil
}

// resolveScanFolder sets cfg.FolderID to the real "oasm-scan" folder ID,
// discovering or creating it as needed. Nessus rejects an unknown folder ID
// (the historical "0" default) at scan-create time.
func resolveScanFolder(client *nessus.Client, cfg *nessusConfig) error {
	resp, err := client.FoldersGet()
	if err != nil {
		return fmt.Errorf("nessus: folders get: %w", err)
	}

	for _, folder := range resp.Folders {
		if folder.Name == oasmScanFolder {
			cfg.FolderID = strconv.Itoa(folder.ID)
			return nil
		}
	}

	created, err := client.FoldersCreate(&nessus.FoldersCreateRequest{Name: oasmScanFolder})
	if err != nil {
		return fmt.Errorf("nessus: create %s folder: %w", oasmScanFolder, err)
	}
	cfg.FolderID = strconv.Itoa(created.ID)
	return nil
}

const oasmScanFolder = "oasm-scan"
