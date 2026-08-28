package main

import (
	"fmt"
	"os"

	"github.com/tencat-dev/nessus-client-go/nessus"
)

// nessusConfig holds the Nessus connection + scan settings, all env-driven.
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

// loadNessusConfig reads the NESSUS_* environment variables. URL, username and
// password are required; the API key pair is optional but must be set together;
// the rest fall back to sane defaults.
func loadNessusConfig() (*nessusConfig, error) {
	cfg := &nessusConfig{
		URL:          os.Getenv("NESSUS_URL"),
		Username:     os.Getenv("NESSUS_USERNAME"),
		Password:     os.Getenv("NESSUS_PASSWORD"),
		AccessKey:    os.Getenv("NESSUS_ACCESS_KEY"),
		SecretKey:    os.Getenv("NESSUS_SECRET_KEY"),
		TemplateUUID: os.Getenv("NESSUS_TEMPLATE_UUID"),
		PolicyID:     os.Getenv("NESSUS_POLICY_ID"),
		FolderID:     os.Getenv("NESSUS_FOLDER_ID"),
	}
	if cfg.FolderID == "" {
		cfg.FolderID = "0"
	}

	if cfg.URL == "" {
		return nil, fmt.Errorf("NESSUS_URL required")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("NESSUS_USERNAME required")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("NESSUS_PASSWORD required")
	}
	if (cfg.AccessKey == "") != (cfg.SecretKey == "") {
		return nil, fmt.Errorf("NESSUS_ACCESS_KEY and NESSUS_SECRET_KEY must be set together")
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
