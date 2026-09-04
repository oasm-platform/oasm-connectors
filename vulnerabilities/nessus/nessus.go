package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/tencat-dev/nessus-client-go/nessus"
)

// nessusConfig holds the Nessus connection + scan settings.
type nessusConfig struct {
	URL          string
	Username     string
	Password     string
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
	Username     string `json:"username"`
	Password     string `json:"password"`
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
// as a legacy fallback for direct-runtime use. URL, username and password are
// required; the API key pair is optional but must be set together; the rest
// fall back to sane defaults.
func loadNessusConfig() (*nessusConfig, error) {
	cfg := &nessusConfig{}

	if raw := strings.TrimSpace(os.Getenv("OASM_CONFIG")); raw != "" {
		var p configProfile
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
		}
		cfg.URL = p.URL
		cfg.Username = p.Username
		cfg.Password = p.Password
		cfg.AccessKey = p.AccessKey
		cfg.SecretKey = p.SecretKey
		cfg.TemplateUUID = p.TemplateUUID
		cfg.PolicyID = p.PolicyID
		cfg.FolderID = p.FolderID
	} else {
		cfg.URL = os.Getenv("NESSUS_URL")
		cfg.Username = os.Getenv("NESSUS_USERNAME")
		cfg.Password = os.Getenv("NESSUS_PASSWORD")
		cfg.AccessKey = os.Getenv("NESSUS_ACCESS_KEY")
		cfg.SecretKey = os.Getenv("NESSUS_SECRET_KEY")
		cfg.TemplateUUID = os.Getenv("NESSUS_TEMPLATE_UUID")
		cfg.PolicyID = os.Getenv("NESSUS_POLICY_ID")
		cfg.FolderID = os.Getenv("NESSUS_FOLDER_ID")
	}

	if cfg.FolderID == "" {
		cfg.FolderID = "0"
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("nessus URL required (config.url or NESSUS_URL)")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("nessus username required (config.username or NESSUS_USERNAME)")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("nessus password required (config.password or NESSUS_PASSWORD)")
	}
	if (cfg.AccessKey == "") != (cfg.SecretKey == "") {
		return nil, fmt.Errorf("access key and secret key must be set together")
	}

	return cfg, nil
}

// newNessusClient performs the auth dance (session → optional API keys) and
// gates on ServerStatus()=="ready" before returning a usable client.
func newNessusClient(cfg *nessusConfig) (*nessus.Client, error) {
	client, err := nessus.NewClient(
		nessus.WithAPIURL(cfg.URL),
		nessus.WithAccount(cfg.Username, cfg.Password),
	)
	if err != nil {
		return nil, fmt.Errorf("nessus: create client: %w", err)
	}

	sess, err := client.SessionCreate()
	if err != nil {
		return nil, fmt.Errorf("nessus: session create: %w", err)
	}
	client.WithToken(sess.Token)

	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		if _, err := client.SessionKeys(&nessus.SessionKeysRequest{
			AccessKey: cfg.AccessKey,
			SecretKey: cfg.SecretKey,
		}); err != nil {
			return nil, fmt.Errorf("nessus: session keys: %w", err)
		}
		client.WithAPIKey(cfg.AccessKey, cfg.SecretKey)
	}

	st, err := client.ServerStatus()
	if err != nil {
		return nil, fmt.Errorf("nessus: server status: %w", err)
	}
	if st.Status != "ready" {
		return nil, fmt.Errorf("nessus: server not ready: status=%q", st.Status)
	}

	return client, nil
}
