package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func clearNessusEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"OASM_CONFIG",
		"NESSUS_URL", "NESSUS_ACCESS_KEY", "NESSUS_SECRET_KEY",
		"NESSUS_TEMPLATE_UUID", "NESSUS_POLICY_ID", "NESSUS_FOLDER_ID",
		"NESSUS_INSECURE",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadNessusConfig_FromOASMConfig(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://nessus.example.com:8834","accessKey":"ak","secretKey":"sk","templateUuid":"tpl-123","policyId":"pol-1","folderId":"42"}`)

	cfg, err := loadNessusConfig(t.Context())
	if err != nil {
		t.Fatalf("loadNessusConfig: %v", err)
	}
	if cfg.URL != "https://nessus.example.com:8834" {
		t.Errorf("URL = %q", cfg.URL)
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
	t.Setenv("OASM_CONFIG", `{"url":"https://nessus.example.com:8834","accessKey":"ak","secretKey":"sk"}`)

	cfg, err := loadNessusConfig(t.Context())
	if err != nil {
		t.Fatalf("loadNessusConfig: %v", err)
	}
	if cfg.FolderID != "" {
		t.Errorf("FolderID = %q, want empty (resolved via oasm-scan discovery)", cfg.FolderID)
	}
	if cfg.TemplateUUID != "" {
		t.Errorf("TemplateUUID = %q, want empty", cfg.TemplateUUID)
	}
}

func TestLoadNessusConfig_Malformed(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{not json`)

	if _, err := loadNessusConfig(t.Context()); err == nil {
		t.Fatal("expected error for malformed OASM_CONFIG")
	}
}

func TestLoadNessusConfig_EnvFallback(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("NESSUS_URL", "https://nessus.example.com:8834")
	t.Setenv("NESSUS_ACCESS_KEY", "ak")
	t.Setenv("NESSUS_SECRET_KEY", "sk")
	t.Setenv("NESSUS_TEMPLATE_UUID", "tpl-env")

	cfg, err := loadNessusConfig(t.Context())
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
	t.Setenv("OASM_CONFIG", `{"accessKey":"ak","secretKey":"sk"}`)

	if _, err := loadNessusConfig(t.Context()); err == nil {
		t.Fatal("expected error for missing url")
	}
}

func TestLoadNessusConfig_MissingKeys(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://nessus.example.com:8834","accessKey":"ak-only"}`)

	if _, err := loadNessusConfig(t.Context()); err == nil {
		t.Fatal("expected error for access key without secret key")
	}
}

func TestLoadNessusConfig_TLSChecksOnByDefault(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://nessus.example.com:8834","accessKey":"ak","secretKey":"sk"}`)

	cfg, err := loadNessusConfig(t.Context())
	if err != nil {
		t.Fatalf("loadNessusConfig: %v", err)
	}
	if cfg.DisableTLSChecks {
		t.Error("DisableTLSChecks = true, want false when the profile omits disableTlsChecks")
	}
}

func TestLoadNessusConfig_DisableTLSChecksFromOASMConfig(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("OASM_CONFIG", `{"url":"https://nessus.example.com:8834","accessKey":"ak","secretKey":"sk","disableTlsChecks":true}`)

	cfg, err := loadNessusConfig(t.Context())
	if err != nil {
		t.Fatalf("loadNessusConfig: %v", err)
	}
	if !cfg.DisableTLSChecks {
		t.Error("DisableTLSChecks = false, want true from disableTlsChecks")
	}
}

func TestLoadNessusConfig_DisableTLSChecksEnvFallback(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("NESSUS_URL", "https://nessus.example.com:8834")
	t.Setenv("NESSUS_ACCESS_KEY", "ak")
	t.Setenv("NESSUS_SECRET_KEY", "sk")
	t.Setenv("NESSUS_INSECURE", "true")

	cfg, err := loadNessusConfig(t.Context())
	if err != nil {
		t.Fatalf("loadNessusConfig: %v", err)
	}
	if !cfg.DisableTLSChecks {
		t.Error("DisableTLSChecks = false, want true from NESSUS_INSECURE")
	}
}

func TestLoadNessusConfig_InvalidInsecureEnv(t *testing.T) {
	clearNessusEnv(t)
	t.Setenv("NESSUS_URL", "https://nessus.example.com:8834")
	t.Setenv("NESSUS_ACCESS_KEY", "ak")
	t.Setenv("NESSUS_SECRET_KEY", "sk")
	t.Setenv("NESSUS_INSECURE", "maybe")

	if _, err := loadNessusConfig(t.Context()); err == nil {
		t.Fatal("expected error for a non-boolean NESSUS_INSECURE")
	}
}

func TestNewNessusHTTPClient_RejectsUntrustedCertificateByDefault(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	hc := newNessusHTTPClient(&nessusConfig{})

	resp, err := hc.Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("request to a self-signed server succeeded, want a certificate error")
	}
}

func TestNewNessusHTTPClient_AcceptsUntrustedCertificateWhenChecksDisabled(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()

	hc := newNessusHTTPClient(&nessusConfig{DisableTLSChecks: true})

	resp, err := hc.Get(srv.URL)
	if err != nil {
		t.Fatalf("request with TLS checks disabled: %v", err)
	}
	resp.Body.Close()
}

func TestNewNessusHTTPClient_KeepsTimeoutAndProxy(t *testing.T) {
	hc := newNessusHTTPClient(&nessusConfig{})

	if hc.Timeout != nessusHTTPTimeout {
		t.Errorf("Timeout = %v, want %v", hc.Timeout, nessusHTTPTimeout)
	}
	tr, ok := hc.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("Transport = %T, want *http.Transport", hc.Transport)
	}
	if tr.Proxy == nil {
		t.Error("Transport.Proxy is nil, want the worker-injected proxy honoured")
	}
}
