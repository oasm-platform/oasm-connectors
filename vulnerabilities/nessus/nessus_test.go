package main

import "testing"

func clearNessusEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"OASM_CONFIG",
		"NESSUS_URL", "NESSUS_USERNAME", "NESSUS_PASSWORD",
		"NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY",
		"NESSUS_TEMPLATE_UUID", "NESSUS_POLICY_ID", "NESSUS_FOLDER_ID",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadNessusConfig_FromOASMConfig(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://nessus.example.com:8834","username":"admin","password":"secret","accessKey":"ak","secretKey":"sk","templateUuid":"tpl-123","policyId":"pol-1","folderId":"42"}`)

	cfg, err := loadNessusConfig()
	if err != nil {
		t.Fatalf("loadNessusConfig: %v", err)
	}
	if cfg.URL != "https://nessus.example.com:8834" {
		t.Errorf("URL = %q", cfg.URL)
	}
	if cfg.Username != "admin" || cfg.Password != "secret" {
		t.Errorf("credentials = %q/%q", cfg.Username, cfg.Password)
	}
	if cfg.AccessKey != "ak" || cfg.SecretKey != "sk" {
		t.Errorf("keys = %q/%q", cfg.AccessKey, cfg.SecretKey)
	}
	if cfg.TemplateUUID != "tpl-123" || cfg.PolicyID != "pol-1" || cfg.FolderID != "42" {
		t.Errorf("scan settings = %q/%q/%q", cfg.TemplateUUID, cfg.PolicyID, cfg.FolderID)
	}
}

func TestLoadNessusConfig_OASMDefaults(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://nessus.example.com:8834","username":"admin","password":"secret"}`)

	cfg, err := loadNessusConfig()
	if err != nil {
		t.Fatalf("loadNessusConfig: %v", err)
	}
	if cfg.FolderID != "0" {
		t.Errorf("FolderID = %q, want default 0", cfg.FolderID)
	}
	if cfg.TemplateUUID != "" {
		t.Errorf("TemplateUUID = %q, want empty", cfg.TemplateUUID)
	}
}

func TestLoadNessusConfig_Malformed(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{not json`)

	if _, err := loadNessusConfig(); err == nil {
		t.Fatal("expected error for malformed OASM_CONFIG")
	}
}

func TestLoadNessusConfig_EnvFallback(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("NESSUS_URL", "https://nessus.example.com:8834")
	t.Setenv("NESSUS_USERNAME", "admin")
	t.Setenv("NESSUS_PASSWORD", "secret")
	t.Setenv("NESSUS_TEMPLATE_UUID", "tpl-env")

	cfg, err := loadNessusConfig()
	if err != nil {
		t.Fatalf("loadNessusConfig: %v", err)
	}
	if cfg.URL != "https://nessus.example.com:8834" {
		t.Errorf("URL = %q", cfg.URL)
	}
	if cfg.TemplateUUID != "tpl-env" {
		t.Errorf("TemplateUUID = %q", cfg.TemplateUUID)
	}
}

func TestLoadNessusConfig_MissingURL(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{"username":"admin","password":"secret"}`)

	if _, err := loadNessusConfig(); err == nil {
		t.Fatal("expected error for missing url")
	}
}

func TestLoadNessusConfig_KeyPairMismatch(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://nessus.example.com:8834","username":"admin","password":"secret","accessKey":"ak-only"}`)

	if _, err := loadNessusConfig(); err == nil {
		t.Fatal("expected error for access key without secret key")
	}
}
