package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	httphelper "github.com/oasm-platform/oasm-connectors/sdk/http"
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
	// DisableTLSChecks skips certificate verification for an on-prem Nessus
	// that serves its default self-signed certificate. Off unless asked for.
	DisableTLSChecks bool
}

// configProfile is the OASM_CONFIG JSON shape the Worker ships per job.
// Keys are camelCase to mirror manifest.yaml configSchema.
type configProfile struct {
	URL              string `json:"url"`
	AccessKey        string `json:"accessKey"`
	SecretKey        string `json:"secretKey"`
	TemplateUUID     string `json:"templateUuid"`
	PolicyID         string `json:"policyId"`
	FolderID         string `json:"folderId"`
	DisableTLSChecks bool   `json:"disableTlsChecks"`
}

// loadNessusConfig reads the Nessus connection + scan settings. The primary
// source is the per-job config profile (connector.LoadConfig: ctx, then
// OASM_CONFIG), so a warm-pool reused container sees its own job's config.
// NESSUS_* env vars remain as a legacy fallback when no profile was shipped.
// URL, access key and secret key are required.
func loadNessusConfig(ctx context.Context) (*nessusConfig, error) {
	cfg := &nessusConfig{}

	if connector.HasConfig(ctx) {
		p, err := connector.LoadConfig[configProfile](ctx)
		if err != nil {
			return nil, err
		}
		cfg.URL = p.URL
		cfg.AccessKey = p.AccessKey
		cfg.SecretKey = p.SecretKey
		cfg.TemplateUUID = p.TemplateUUID
		cfg.PolicyID = p.PolicyID
		cfg.FolderID = p.FolderID
		cfg.DisableTLSChecks = p.DisableTLSChecks
	} else {
		cfg.URL = os.Getenv("NESSUS_URL")
		cfg.AccessKey = os.Getenv("NESSUS_ACCESS_KEY")
		cfg.SecretKey = os.Getenv("NESSUS_SECRET_KEY")
		cfg.TemplateUUID = os.Getenv("NESSUS_TEMPLATE_UUID")
		cfg.PolicyID = os.Getenv("NESSUS_POLICY_ID")
		cfg.FolderID = os.Getenv("NESSUS_FOLDER_ID")

		if raw := strings.TrimSpace(os.Getenv("NESSUS_INSECURE")); raw != "" {
			v, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid NESSUS_INSECURE: %w", err)
			}
			cfg.DisableTLSChecks = v
		}
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("nessus URL required (config.url or NESSUS_URL)")
	}
	if cfg.AccessKey == "" || cfg.SecretKey == "" {
		return nil, fmt.Errorf("nessus access key and secret key required (config.accessKey/secretKey or NESSUS_ACCESS_KEY/NESSUS_SECRET_KEY)")
	}

	return cfg, nil
}

// nessusHTTPTimeout bounds a single Nessus API call. The client dependency
// ships http.Client.Timeout=0 and takes no context, so without this a stalled
// Nessus server would block the connector until the container is killed.
const nessusHTTPTimeout = 60 * time.Second

// newNessusHTTPClient is the transport every Nessus API call goes through:
// the shared proxy-aware client, bounded by nessusHTTPTimeout, verifying the
// server certificate unless cfg.DisableTLSChecks is set.
func newNessusHTTPClient(cfg *nessusConfig) *http.Client {
	return httphelper.NewClient(
		httphelper.WithTimeout(nessusHTTPTimeout),
		httphelper.WithInsecureSkipVerify(cfg.DisableTLSChecks),
	)
}

// newNessusClient builds a client that authenticates every request with the
// API access/secret key pair (X-ApiKeys header), then gates on
// ServerStatus()=="ready" before returning it.
func newNessusClient(cfg *nessusConfig) (*nessus.Client, error) {
	// The dependency installs its own retryablehttp client with
	// InsecureSkipVerify and no timeout; supplying our own adds the timeout and
	// verifies the certificate unless the profile opts out.
	req := retryablehttp.NewClient()
	req.HTTPClient = newNessusHTTPClient(cfg)

	client, err := nessus.NewClient(
		nessus.WithAPIURL(cfg.URL),
		nessus.WithAPIKey(cfg.AccessKey, cfg.SecretKey),
		nessus.WithRequest(req),
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
