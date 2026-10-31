package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func useTempCache(t *testing.T) {
	t.Helper()
	prev := customTemplateCacheDir
	customTemplateCacheDir = t.TempDir()
	t.Cleanup(func() { customTemplateCacheDir = prev })
}

func readStaged(t *testing.T, dir, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(data)
}

func TestStageCustomTemplatesInlineAndURL(t *testing.T) {
	useTempCache(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write([]byte("id: from-url\n"))
	}))
	defer srv.Close()

	templates := []CustomTemplate{
		{Content: "id: inline\n"},
		{URL: srv.URL, CacheKey: "3f1c-1700000000000"},
	}
	dir, err := stageCustomTemplates(context.Background(), templates)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer os.RemoveAll(dir)

	if got := readStaged(t, dir, "0.yaml"); got != "id: inline\n" {
		t.Errorf("0.yaml = %q", got)
	}
	if got := readStaged(t, dir, "1.yaml"); got != "id: from-url\n" {
		t.Errorf("1.yaml = %q", got)
	}

	// Same cache key on the next job: served from cache, no second download.
	dir2, err := stageCustomTemplates(context.Background(), templates[1:])
	if err != nil {
		t.Fatalf("stage again: %v", err)
	}
	defer os.RemoveAll(dir2)
	if got := readStaged(t, dir2, "0.yaml"); got != "id: from-url\n" {
		t.Errorf("cached 0.yaml = %q", got)
	}
	if hits.Load() != 1 {
		t.Errorf("downloads = %d, want 1", hits.Load())
	}
}

func TestStageCustomTemplatesUnsafeCacheKeyIsNotCached(t *testing.T) {
	useTempCache(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write([]byte("id: x\n"))
	}))
	defer srv.Close()

	for i := 0; i < 2; i++ {
		dir, err := stageCustomTemplates(context.Background(), []CustomTemplate{{URL: srv.URL, CacheKey: "../escape"}})
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		os.RemoveAll(dir)
	}
	if hits.Load() != 2 {
		t.Errorf("downloads = %d, want 2 (unsafe key must bypass the cache)", hits.Load())
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(customTemplateCacheDir), "escape.yaml")); err == nil {
		t.Errorf("cache key escaped the cache dir")
	}
}

func TestStageCustomTemplatesErrors(t *testing.T) {
	useTempCache(t)
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer notFound.Close()
	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("a", maxCustomTemplateBytes+1)))
	}))
	defer huge.Close()

	cases := map[string]CustomTemplate{
		"empty":          {},
		"bad status":     {URL: notFound.URL},
		"oversize url":   {URL: huge.URL},
		"oversize value": {Content: strings.Repeat("a", maxCustomTemplateBytes+1)},
	}
	for name, tpl := range cases {
		t.Run(name, func(t *testing.T) {
			dir, err := stageCustomTemplates(context.Background(), []CustomTemplate{tpl})
			if err == nil {
				os.RemoveAll(dir)
				t.Fatalf("want error")
			}
		})
	}
}

func TestScanParamsCustomTemplatesDropFilters(t *testing.T) {
	cfg := Config{
		Severity:        []string{"high"},
		Tags:            []string{"cve"},
		ExcludeTags:     []string{"dos"},
		TemplateIds:     []string{"x"},
		CustomTemplates: []CustomTemplate{{Content: "id: a\n"}},
	}
	p := scanParams(cfg, "/staged")
	assertSliceEqual(t, "templates", p.templates, []string{"/staged"})
	if p.filters.Severity != "" || p.filters.Tags != nil || p.filters.ExcludeTags != nil || p.filters.IDs != nil {
		t.Errorf("filters = %+v, want none", p.filters)
	}
	if p.idMode {
		t.Errorf("idMode = true, want false")
	}
}

// In local dev core-api signs template URLs against http://localhost:9000,
// which inside the connector container is the container itself.
func TestDownloadTemplateLoopbackFallsBackToHostGateway(t *testing.T) {
	var gotHost atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
		w.Write([]byte("id: via-gateway\n"))
	}))
	defer srv.Close()
	port := srv.Listener.Addr().(*net.TCPAddr).Port

	// Nothing listens on 127.0.0.2; the "gateway" is the server on 127.0.0.1.
	prev := loopbackFallbackHost
	loopbackFallbackHost = "127.0.0.1"
	t.Cleanup(func() { loopbackFallbackHost = prev })

	signedHost := fmt.Sprintf("127.0.0.2:%d", port)
	data, err := downloadTemplate(context.Background(), "http://"+signedHost+"/t.yaml")
	if err != nil {
		t.Fatalf("download: %v", err)
	}
	if string(data) != "id: via-gateway\n" {
		t.Errorf("data = %q", data)
	}
	// The presigned signature covers Host: only the dial target may change.
	if gotHost.Load() != signedHost {
		t.Errorf("Host = %v, want %s", gotHost.Load(), signedHost)
	}
}
