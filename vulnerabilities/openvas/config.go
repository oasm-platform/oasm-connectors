package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// openvasConfig holds the gvmd connection + scan settings.
type openvasConfig struct {
	Host             string
	Port             int
	Username         string
	Password         string
	CACert           string
	ClientCert       string
	ClientKey        string
	DisableTLSChecks bool
	ScannerID        string
	ConfigID         string
	PortListID       string
}

// configProfile is the OASM_CONFIG JSON shape the Worker ships per job.
// Keys are camelCase to mirror manifest.yaml configSchema.
type configProfile struct {
	Host             string `json:"host"`
	Port             *int   `json:"port"`
	Username         string `json:"username"`
	Password         string `json:"password"`
	CACert           string `json:"caCert"`
	ClientCert       string `json:"clientCert"`
	ClientKey        string `json:"clientKey"`
	DisableTLSChecks bool   `json:"disableTlsChecks"`
	ScannerID        string `json:"scannerId"`
	ConfigID         string `json:"configId"`
	PortListID       string `json:"portListId"`
}

// Built-in GMP defaults. The scanner id is Greenbone's built-in OpenVAS
// scanner; the config id is "Full and fast".
const (
	defaultGMPPort      = 9390
	defaultScannerID    = "08b69003-5fc2-4037-a479-93b440211c73"
	defaultScanConfigID = "daba56c8-73ec-11df-a475-002264764cea"
)

// loadOpenVASConfig reads the gvmd connection + scan settings. The primary
// source is OASM_CONFIG (the per-job config profile) — the SDK runtime
// overrides that env var per execution so a warm-pool reused container sees
// its own job's config rather than its first-run env. OPENVAS_* env vars remain
// as a legacy fallback for direct-runtime use. It is called per execution from
// Execute, never at package init. Secrets are never logged here.
func loadOpenVASConfig() (*openvasConfig, error) {
	cfg := &openvasConfig{}

	if raw := strings.TrimSpace(os.Getenv("OASM_CONFIG")); raw != "" {
		var p configProfile
		if err := json.Unmarshal([]byte(raw), &p); err != nil {
			return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
		}
		cfg.Host = p.Host
		cfg.Username = p.Username
		cfg.Password = p.Password
		cfg.CACert = p.CACert
		cfg.ClientCert = p.ClientCert
		cfg.ClientKey = p.ClientKey
		cfg.DisableTLSChecks = p.DisableTLSChecks
		cfg.ScannerID = p.ScannerID
		cfg.ConfigID = p.ConfigID
		cfg.PortListID = p.PortListID
		if p.Port != nil {
			cfg.Port = *p.Port
		}
	} else {
		cfg.Host = os.Getenv("OPENVAS_HOST")
		cfg.Username = os.Getenv("OPENVAS_USERNAME")
		cfg.Password = os.Getenv("OPENVAS_PASSWORD")
		cfg.CACert = os.Getenv("OPENVAS_CA_CERT")
		cfg.ClientCert = os.Getenv("OPENVAS_CLIENT_CERT")
		cfg.ClientKey = os.Getenv("OPENVAS_CLIENT_KEY")
		cfg.ScannerID = os.Getenv("OPENVAS_SCANNER_ID")
		cfg.ConfigID = os.Getenv("OPENVAS_CONFIG_ID")
		cfg.PortListID = os.Getenv("OPENVAS_PORT_LIST_ID")

		if raw := strings.TrimSpace(os.Getenv("OPENVAS_PORT")); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid OPENVAS_PORT: %w", err)
			}
			cfg.Port = v
		}
		if raw := strings.TrimSpace(os.Getenv("OPENVAS_INSECURE")); raw != "" {
			v, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid OPENVAS_INSECURE: %w", err)
			}
			cfg.DisableTLSChecks = v
		}
	}

	if cfg.Host == "" {
		return nil, fmt.Errorf("openvas host required (config.host or OPENVAS_HOST)")
	}
	if cfg.Username == "" {
		return nil, fmt.Errorf("openvas username required (config.username or OPENVAS_USERNAME)")
	}
	if cfg.Password == "" {
		return nil, fmt.Errorf("openvas password required (config.password or OPENVAS_PASSWORD)")
	}

	if cfg.Port == 0 {
		cfg.Port = defaultGMPPort
	}
	if cfg.ScannerID == "" {
		cfg.ScannerID = defaultScannerID
	}
	if cfg.ConfigID == "" {
		cfg.ConfigID = defaultScanConfigID
	}

	if (cfg.ClientCert == "") != (cfg.ClientKey == "") {
		return nil, fmt.Errorf("openvas clientCert and clientKey must be set together")
	}

	return cfg, nil
}
