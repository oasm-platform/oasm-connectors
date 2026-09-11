package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// wpscanConfig mirrors manifest.yaml configSchema. Keys are camelCase to match
// the OASM_CONFIG JSON shape the Worker ships per job.
type wpscanConfig struct {
	Force                   bool     `json:"force"`
	IgnoreMainRedirect      bool     `json:"ignoreMainRedirect"`
	DisableTLSChecks        bool     `json:"disableTlsChecks"`
	Server                  string   `json:"server"`
	Scope                   []string `json:"scope"`
	Vhost                   string   `json:"vhost"`
	APIToken                string   `json:"apiToken"`
	HTTPAuth                string   `json:"httpAuth"`
	UserAgent               string   `json:"userAgent"`
	RandomUserAgent         bool     `json:"randomUserAgent"`
	CookieString            string   `json:"cookieString"`
	Headers                 string   `json:"headers"`
	Enumerate               []string `json:"enumerate"`
	ExcludeContentBased     string   `json:"excludeContentBased"`
	ExcludeUsernames        string   `json:"excludeUsernames"`
	DetectionMode           string   `json:"detectionMode"`
	PluginsDetection        string   `json:"pluginsDetection"`
	PluginsVersionDetection string   `json:"pluginsVersionDetection"`
	ThemesDetection         string   `json:"themesDetection"`
	ThemesVersionDetection  string   `json:"themesVersionDetection"`
	MaxThreads              int      `json:"maxThreads"`
	Throttle                int      `json:"throttle"`
	RequestTimeout          int      `json:"requestTimeout"`
	ConnectTimeout          int      `json:"connectTimeout"`
	Proxy                   string   `json:"proxy"`
	Stealthy                bool     `json:"stealthy"`
	Update                  *bool    `json:"update"`
}

// loadWpscanConfig reads the per-job config profile from OASM_CONFIG. An unset
// or empty value yields a zero config (all wpscan defaults), not an error.
func loadWpscanConfig() (*wpscanConfig, error) {
	raw := strings.TrimSpace(os.Getenv("OASM_CONFIG"))
	if raw == "" {
		return &wpscanConfig{}, nil
	}
	var cfg wpscanConfig
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return nil, fmt.Errorf("invalid OASM_CONFIG: %w", err)
	}
	return &cfg, nil
}

// buildWpscanArgs assembles the wpscan CLI arg vector. Zero values are omitted
// so only explicitly configured options are passed; Update is tri-state (nil
// emits neither --update nor --no-update).
func buildWpscanArgs(target string, cfg *wpscanConfig) []string {
	args := []string{"--url", target, "--format", "json", "--no-banner"}

	if cfg.Force {
		args = append(args, "--force")
	}
	if cfg.IgnoreMainRedirect {
		args = append(args, "--ignore-main-redirect")
	}
	if cfg.DisableTLSChecks {
		args = append(args, "--disable-tls-checks")
	}
	if cfg.Stealthy {
		args = append(args, "--stealthy")
	}
	if cfg.RandomUserAgent {
		args = append(args, "--random-user-agent")
	}
	if cfg.Server != "" {
		args = append(args, "--server", cfg.Server)
	}
	if len(cfg.Scope) > 0 {
		args = append(args, "--scope", strings.Join(cfg.Scope, ","))
	}
	if cfg.Vhost != "" {
		args = append(args, "--vhost", cfg.Vhost)
	}
	if cfg.HTTPAuth != "" {
		args = append(args, "--http-auth", cfg.HTTPAuth)
	}
	if cfg.APIToken != "" {
		args = append(args, "--api-token", cfg.APIToken)
	}
	if cfg.UserAgent != "" {
		args = append(args, "--user-agent", cfg.UserAgent)
	}
	if cfg.CookieString != "" {
		args = append(args, "--cookie-string", cfg.CookieString)
	}
	if cfg.Headers != "" {
		args = append(args, "--headers", cfg.Headers)
	}
	if len(cfg.Enumerate) > 0 {
		args = append(args, "-e", strings.Join(cfg.Enumerate, ","))
	}
	if cfg.ExcludeContentBased != "" {
		args = append(args, "--exclude-content-based", cfg.ExcludeContentBased)
	}
	if cfg.ExcludeUsernames != "" {
		args = append(args, "--exclude-usernames", cfg.ExcludeUsernames)
	}
	if cfg.DetectionMode != "" {
		args = append(args, "--detection-mode", cfg.DetectionMode)
	}
	if cfg.PluginsDetection != "" {
		args = append(args, "--plugins-detection", cfg.PluginsDetection)
	}
	if cfg.PluginsVersionDetection != "" {
		args = append(args, "--plugins-version-detection", cfg.PluginsVersionDetection)
	}
	if cfg.ThemesDetection != "" {
		args = append(args, "--themes-detection", cfg.ThemesDetection)
	}
	if cfg.ThemesVersionDetection != "" {
		args = append(args, "--themes-version-detection", cfg.ThemesVersionDetection)
	}
	if cfg.MaxThreads > 0 {
		args = append(args, "--max-threads", strconv.Itoa(cfg.MaxThreads))
	}
	if cfg.Throttle > 0 {
		args = append(args, "--throttle", strconv.Itoa(cfg.Throttle))
	}
	if cfg.RequestTimeout > 0 {
		args = append(args, "--request-timeout", strconv.Itoa(cfg.RequestTimeout))
	}
	if cfg.ConnectTimeout > 0 {
		args = append(args, "--connect-timeout", strconv.Itoa(cfg.ConnectTimeout))
	}
	if cfg.Proxy != "" {
		args = append(args, "--proxy", cfg.Proxy)
	}
	if cfg.Update != nil {
		if *cfg.Update {
			args = append(args, "--update")
		} else {
			args = append(args, "--no-update")
		}
	}

	return args
}
