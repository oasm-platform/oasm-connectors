package main

import "testing"

func clearOpenVASEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"OASM_CONFIG",
		"OPENVAS_HOST", "OPENVAS_PORT", "OPENVAS_USERNAME", "OPENVAS_PASSWORD",
		"OPENVAS_CA_CERT", "OPENVAS_CLIENT_CERT", "OPENVAS_CLIENT_KEY",
		"OPENVAS_INSECURE", "OPENVAS_SCANNER_ID", "OPENVAS_CONFIG_ID",
		"OPENVAS_PORT_LIST_ID",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadOpenVASConfig_FromOASMConfig(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OASM_CONFIG", `{"host":"gvmd.example.com","port":9391,"username":"admin","password":"pw","caCert":"<ca>","clientCert":"<cert>","clientKey":"<key>","disableTlsChecks":true,"scannerId":"scan-1","configId":"cfg-1","portListId":"pl-1"}`)

	cfg, err := loadOpenVASConfig()
	if err != nil {
		t.Fatalf("loadOpenVASConfig: %v", err)
	}
	if cfg.Host != "gvmd.example.com" {
		t.Errorf("Host = %q", cfg.Host)
	}
	if cfg.Port != 9391 {
		t.Errorf("Port = %d, want 9391", cfg.Port)
	}
	if cfg.Username != "admin" || cfg.Password != "pw" {
		t.Errorf("credentials = %q/%q", cfg.Username, cfg.Password)
	}
	if cfg.CACert != "<ca>" || cfg.ClientCert != "<cert>" || cfg.ClientKey != "<key>" {
		t.Errorf("tls material = %q/%q/%q", cfg.CACert, cfg.ClientCert, cfg.ClientKey)
	}
	if !cfg.DisableTLSChecks {
		t.Error("DisableTLSChecks = false, want true")
	}
	if cfg.ScannerID != "scan-1" || cfg.ConfigID != "cfg-1" || cfg.PortListID != "pl-1" {
		t.Errorf("scan settings = %q/%q/%q", cfg.ScannerID, cfg.ConfigID, cfg.PortListID)
	}
}

func TestLoadOpenVASConfig_OASMDefaults(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OASM_CONFIG", `{"host":"gvmd.example.com","username":"admin","password":"pw"}`)

	cfg, err := loadOpenVASConfig()
	if err != nil {
		t.Fatalf("loadOpenVASConfig: %v", err)
	}
	if cfg.Port != defaultGMPPort {
		t.Errorf("Port = %d, want %d", cfg.Port, defaultGMPPort)
	}
	if cfg.ScannerID != defaultScannerID {
		t.Errorf("ScannerID = %q, want %q", cfg.ScannerID, defaultScannerID)
	}
	if cfg.ConfigID != defaultScanConfigID {
		t.Errorf("ConfigID = %q, want %q", cfg.ConfigID, defaultScanConfigID)
	}
	if cfg.PortListID != "" {
		t.Errorf("PortListID = %q, want empty", cfg.PortListID)
	}
	if cfg.DisableTLSChecks {
		t.Error("DisableTLSChecks = true, want false")
	}
}

func TestLoadOpenVASConfig_Malformed(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OASM_CONFIG", `{not json`)

	if _, err := loadOpenVASConfig(); err == nil {
		t.Fatal("expected error for malformed OASM_CONFIG")
	}
}

func TestLoadOpenVASConfig_MissingHost(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OASM_CONFIG", `{"username":"admin","password":"pw"}`)

	if _, err := loadOpenVASConfig(); err == nil {
		t.Fatal("expected error for missing host")
	}
}

func TestLoadOpenVASConfig_MissingUsername(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OASM_CONFIG", `{"host":"gvmd.example.com","password":"pw"}`)

	if _, err := loadOpenVASConfig(); err == nil {
		t.Fatal("expected error for missing username")
	}
}

func TestLoadOpenVASConfig_MissingPassword(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OASM_CONFIG", `{"host":"gvmd.example.com","username":"admin"}`)

	if _, err := loadOpenVASConfig(); err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestLoadOpenVASConfig_EnvFallback(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OPENVAS_HOST", "gvmd.env.example.com")
	t.Setenv("OPENVAS_PORT", "9392")
	t.Setenv("OPENVAS_USERNAME", "env-admin")
	t.Setenv("OPENVAS_PASSWORD", "env-pw")
	t.Setenv("OPENVAS_INSECURE", "true")
	t.Setenv("OPENVAS_SCANNER_ID", "env-scan")
	t.Setenv("OPENVAS_CONFIG_ID", "env-cfg")
	t.Setenv("OPENVAS_PORT_LIST_ID", "env-pl")

	cfg, err := loadOpenVASConfig()
	if err != nil {
		t.Fatalf("loadOpenVASConfig: %v", err)
	}
	if cfg.Host != "gvmd.env.example.com" {
		t.Errorf("Host = %q", cfg.Host)
	}
	if cfg.Port != 9392 {
		t.Errorf("Port = %d, want 9392", cfg.Port)
	}
	if cfg.Username != "env-admin" || cfg.Password != "env-pw" {
		t.Errorf("credentials = %q/%q", cfg.Username, cfg.Password)
	}
	if !cfg.DisableTLSChecks {
		t.Error("DisableTLSChecks = false, want true")
	}
	if cfg.ScannerID != "env-scan" || cfg.ConfigID != "env-cfg" || cfg.PortListID != "env-pl" {
		t.Errorf("scan settings = %q/%q/%q", cfg.ScannerID, cfg.ConfigID, cfg.PortListID)
	}
}

func TestLoadOpenVASConfig_ClientCertWithoutKey(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OASM_CONFIG", `{"host":"gvmd.example.com","username":"admin","password":"pw","clientCert":"<cert>"}`)

	if _, err := loadOpenVASConfig(); err == nil {
		t.Fatal("expected error for clientCert without clientKey")
	}
}

func TestLoadOpenVASConfig_ClientKeyWithoutCert(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OASM_CONFIG", `{"host":"gvmd.example.com","username":"admin","password":"pw","clientKey":"<key>"}`)

	if _, err := loadOpenVASConfig(); err == nil {
		t.Fatal("expected error for clientKey without clientCert")
	}
}

func TestLoadOpenVASConfig_InvalidEnvInsecure(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OPENVAS_HOST", "gvmd.example.com")
	t.Setenv("OPENVAS_USERNAME", "admin")
	t.Setenv("OPENVAS_PASSWORD", "pw")
	t.Setenv("OPENVAS_INSECURE", "maybe")

	if _, err := loadOpenVASConfig(); err == nil {
		t.Fatal("expected error for invalid OPENVAS_INSECURE")
	}
}

func TestLoadOpenVASConfig_InvalidEnvPort(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OPENVAS_HOST", "gvmd.example.com")
	t.Setenv("OPENVAS_USERNAME", "admin")
	t.Setenv("OPENVAS_PASSWORD", "pw")
	t.Setenv("OPENVAS_PORT", "not-a-port")

	if _, err := loadOpenVASConfig(); err == nil {
		t.Fatal("expected error for invalid OPENVAS_PORT")
	}
}
