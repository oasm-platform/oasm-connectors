package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// CustomTemplate is one user template shipped with the job: inline Content
// (agent runs) or a presigned URL (saved workspace templates). CacheKey names
// the cached download and changes whenever the template is saved again.
type CustomTemplate struct {
	URL      string `json:"url"`
	CacheKey string `json:"cacheKey"`
	Content  string `json:"content"`
}

// maxCustomTemplateBytes matches the server-side template size cap.
const maxCustomTemplateBytes = 256 * 1024

// customTemplateCacheDir lives on the container's /tmp tmpfs, so it dies with
// the container. A var so tests can point it elsewhere.
// shortcut: no eviction, bounded by the container's lifetime; add an LRU if warm containers live long enough to fill tmpfs.
var customTemplateCacheDir = filepath.Join(os.TempDir(), "oasm-templates")

var cacheKeyPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,128}$`)

// loopbackFallbackHost is retried when a loopback template URL refuses: in
// local dev core-api signs URLs against http://localhost:9000, which inside
// this container is the container itself; the worker maps this name to the
// Docker host. A var so tests can point it elsewhere.
var loopbackFallbackHost = "host.docker.internal"

var templateHTTPClient = newTemplateHTTPClient()

func newTemplateHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = dialWithLoopbackFallback
	return &http.Client{Timeout: 30 * time.Second, Transport: transport}
}

// dialWithLoopbackFallback only swaps the dial target: the URL and Host
// header stay as signed, so the presigned signature still verifies.
func dialWithLoopbackFallback(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err == nil {
		return conn, nil
	}
	host, port, splitErr := net.SplitHostPort(addr)
	if splitErr != nil || !isLoopbackHost(host) {
		return nil, err
	}
	conn, fallbackErr := d.DialContext(ctx, network, net.JoinHostPort(loopbackFallbackHost, port))
	if fallbackErr != nil {
		return nil, errors.Join(err, fallbackErr)
	}
	return conn, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// stageCustomTemplates writes this job's templates into a fresh directory and
// returns it; the caller removes it. File names are generated (0.yaml, ...)
// so nothing from the job config reaches a path. The cache is never handed to
// nuclei directly: the warm pool shares a container across workspaces and
// nuclei loads every file in the directory it is given.
func stageCustomTemplates(ctx context.Context, templates []CustomTemplate) (string, error) {
	dir, err := os.MkdirTemp("", "oasm-custom-")
	if err != nil {
		return "", fmt.Errorf("custom templates dir: %w", err)
	}
	for i, t := range templates {
		data, err := customTemplateContent(ctx, t)
		if err != nil {
			os.RemoveAll(dir)
			return "", fmt.Errorf("custom template %d: %w", i, err)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%d.yaml", i)), data, 0o600); err != nil {
			os.RemoveAll(dir)
			return "", fmt.Errorf("custom template %d: %w", i, err)
		}
	}
	return dir, nil
}

func customTemplateContent(ctx context.Context, t CustomTemplate) ([]byte, error) {
	if t.Content != "" {
		if len(t.Content) > maxCustomTemplateBytes {
			return nil, fmt.Errorf("content exceeds %d bytes", maxCustomTemplateBytes)
		}
		return []byte(t.Content), nil
	}
	if t.URL == "" {
		return nil, fmt.Errorf("needs url or content")
	}

	cacheable := cacheKeyPattern.MatchString(t.CacheKey)
	cachePath := filepath.Join(customTemplateCacheDir, t.CacheKey+".yaml")
	if cacheable {
		if data, err := os.ReadFile(cachePath); err == nil {
			return data, nil
		}
	}

	data, err := downloadTemplate(ctx, t.URL)
	if err != nil {
		return nil, err
	}
	if cacheable {
		// Best effort: a failed cache write only costs a re-download.
		_ = writeCacheFile(cachePath, data)
	}
	return data, nil
}

func downloadTemplate(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	resp, err := templateHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download: status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCustomTemplateBytes+1))
	if err != nil {
		return nil, fmt.Errorf("download: %w", err)
	}
	if len(data) > maxCustomTemplateBytes {
		return nil, fmt.Errorf("download exceeds %d bytes", maxCustomTemplateBytes)
	}
	return data, nil
}

// writeCacheFile renames a temp file into place so a concurrent execution in
// the same container never reads a half-written template.
func writeCacheFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".partial-")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
