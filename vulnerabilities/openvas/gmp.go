package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// defaultGMPTimeout bounds a single request/response exchange when the caller's
// context carries no deadline. The overall scan is bounded by the Worker's job
// timeout; this only guards one GMP round-trip.
const defaultGMPTimeout = 60 * time.Second

// maxDocumentBytes caps a single GMP response document. Exceeding it is a
// deterministic failure (a retry cannot help). This guards the decision, not
// peak memory: a single oversize document still fails the run. For very large
// scans prefer chunked get_results (bounded rows/paging) over one rows=-1
// document.
const maxDocumentBytes = 128 << 20

// captureReader wraps the TLS connection and records every byte it hands to the
// XML decoder. The decoder reads FROM this reader, so the captured stream is
// exactly the decoder's input. A per-call tee reader sitting outside the
// decoder's read path cannot observe the bytes the decoder consumes.
type captureReader struct {
	r   io.Reader
	buf bytes.Buffer
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 {
		c.buf.Write(p[:n])
	}
	return n, err
}

// gmpConn owns one GMP-over-TLS connection: the socket, its capture reader, and
// the single persistent XML decoder shared across commands. Commands reuse the
// connection; it is never closed per command.
type gmpConn struct {
	conn net.Conn
	cr   *captureReader
	dec  *xml.Decoder

	// base is the absolute stream offset of the first byte still held in
	// cr.buf. readDocument trims the already-consumed prefix on each call so
	// the capture buffer does not grow unbounded across polls.
	base int64
}

// dialGMP establishes a context-aware TLS/TCP connection to gvmd and wraps it in
// a capture reader + XML decoder. Every returned error carries exactly one
// fatal:/retryable: prefix.
func dialGMP(ctx context.Context, cfg *openvasConfig) (*gmpConn, error) {
	tlsCfg := &tls.Config{
		// #nosec G402 -- operator-controlled opt-out for self-signed test gvmd.
		InsecureSkipVerify: cfg.DisableTLSChecks,
		ServerName:         cfg.Host,
		MinVersion:         tls.VersionTLS12,
	}

	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, errors.New("fatal: openvas: parse CA certificate: no PEM certificate found")
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.X509KeyPair([]byte(cfg.ClientCert), []byte(cfg.ClientKey))
		if err != nil {
			return nil, fmt.Errorf("fatal: openvas: load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("retryable: openvas: dial %s: %w", addr, err)
	}

	tc := tls.Client(raw, tlsCfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		if isCertVerifyError(err) {
			return nil, fmt.Errorf("fatal: openvas: tls verify %s: %w", addr, err)
		}
		return nil, fmt.Errorf("retryable: openvas: tls handshake %s: %w", addr, err)
	}

	cr := &captureReader{r: tc}
	return &gmpConn{conn: tc, cr: cr, dec: xml.NewDecoder(cr)}, nil
}

// isCertVerifyError reports whether a handshake failure was a server-certificate
// verification failure. Retrying cannot help, so it is classified fatal.
func isCertVerifyError(err error) bool {
	var cve *tls.CertificateVerificationError
	if errors.As(err, &cve) {
		return true
	}
	var unk x509.UnknownAuthorityError
	if errors.As(err, &unk) {
		return true
	}
	var host x509.HostnameError
	return errors.As(err, &host)
}

// send writes one newline-terminated GMP request and reads exactly one response
// document. A non-2xx status is returned as *gmpError; when out is non-nil the
// raw 2xx document is decoded into it. Every error carries exactly one
// fatal:/retryable: prefix.
func (c *gmpConn) send(ctx context.Context, request string, out any) error {
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(defaultGMPTimeout)
	}
	if err := c.conn.SetDeadline(dl); err != nil {
		return fmt.Errorf("retryable: openvas: set deadline: %w", err)
	}

	// Unblock a stalled read as soon as ctx is cancelled rather than waiting
	// for the deadline. Stopped via done when the read returns.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = c.conn.SetDeadline(time.Now())
		case <-done:
		}
	}()

	if _, err := io.WriteString(c.conn, request+"\n"); err != nil {
		// A mid-send cancel is unblocked by the watcher's deadline, which
		// surfaces as i/o timeout; the context is the real cause.
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("retryable: openvas: cancelled: %w", cerr)
		}
		return fmt.Errorf("retryable: openvas: write request: %w", err)
	}

	raw, err := c.readDocument(ctx)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return fmt.Errorf("retryable: openvas: cancelled: %w", cerr)
		}
		return err
	}

	var env struct {
		XMLName    xml.Name
		Status     string `xml:"status,attr"`
		StatusText string `xml:"status_text,attr"`
	}
	if err := xml.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("fatal: openvas: parse response envelope: %w", err)
	}
	if env.Status == "" {
		return errors.New("fatal: openvas: parse response envelope: missing status attribute")
	}
	if !strings.HasPrefix(env.Status, "2") {
		return &gmpError{Command: env.XMLName.Local, Code: env.Status, Text: env.StatusText}
	}
	if out != nil {
		if err := xml.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("fatal: openvas: decode %s response: %w", env.XMLName.Local, err)
		}
	}
	return nil
}

// readDocument consumes exactly one top-level XML document from the persistent
// decoder and returns its raw bytes, using absolute stream offsets. Whitespace,
// comments, and processing instructions between documents are skipped.
func (c *gmpConn) readDocument(ctx context.Context) ([]byte, error) {
	// Apply the ctx deadline so a stalled read cannot hang past it. Skip when
	// ctx is already cancelled so an in-flight watcher SetDeadline(time.Now())
	// is not overwritten with a future deadline.
	if dl, ok := ctx.Deadline(); ok && ctx.Err() == nil {
		if err := c.conn.SetDeadline(dl); err != nil {
			return nil, fmt.Errorf("retryable: openvas: set deadline: %w", err)
		}
	}

	start := c.dec.InputOffset()

	// Drop the already-consumed prefix so cr.buf tracks only unread bytes.
	if n := start - c.base; n > 0 {
		c.cr.buf.Next(int(n))
		c.base = start
	}

	depth := 0
	for {
		tok, err := c.dec.Token()
		if err != nil {
			return nil, classifyReadError(err)
		}
		switch tok.(type) {
		case xml.StartElement:
			depth++
		case xml.EndElement:
			depth--
			if depth == 0 {
				end := c.dec.InputOffset()
				if end-start > maxDocumentBytes {
					return nil, fmt.Errorf("fatal: openvas: response exceeds %d bytes", maxDocumentBytes)
				}
				return c.cr.buf.Bytes()[start-c.base : end-c.base], nil
			}
		}
	}
}

// classifyReadError maps a decoder error to a prefixed error. A document
// truncated by a connection close is retryable; encoding/xml reports that as an
// *xml.SyntaxError with an "unexpected EOF" message (io.ErrUnexpectedEOF is not
// what the XML decoder returns), so both spellings are recognized.
func classifyReadError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("retryable: openvas: incomplete response: %w", err)
	}
	var se *xml.SyntaxError
	if errors.As(err, &se) {
		if strings.Contains(se.Msg, "EOF") {
			// Truncated by a connection close — retrying may help.
			return fmt.Errorf("retryable: openvas: incomplete response: %w", err)
		}
		// A malformed document is a protocol violation; a retry cannot help.
		return fmt.Errorf("fatal: openvas: malformed response: %w", err)
	}
	return fmt.Errorf("retryable: openvas: read response: %w", err)
}

// authenticate sends the GMP authenticate command. A failed login is returned
// by gvmd as status="400" status_text="Authentication failed" (not 401), which
// send surfaces as a fatal *gmpError.
func (c *gmpConn) authenticate(ctx context.Context, username, password string) error {
	req := struct {
		XMLName     xml.Name `xml:"authenticate"`
		Credentials struct {
			Username string `xml:"username"`
			Password string `xml:"password"`
		} `xml:"credentials"`
	}{}
	req.Credentials.Username = username
	req.Credentials.Password = password
	raw, err := xml.Marshal(req)
	if err != nil {
		return fmt.Errorf("fatal: openvas: build authenticate request: %w", err)
	}
	var out struct{ XMLName xml.Name }
	return c.send(ctx, string(raw), &out)
}

// gmpError is a GMP command failure. 4xx statuses are fatal (configuration,
// credentials, permissions, missing resources); 5xx statuses are retryable.
type gmpError struct {
	Command string
	Code    string
	Text    string
}

func (e *gmpError) Fatal() bool { return strings.HasPrefix(e.Code, "4") }

// Error carries its own fatal:/retryable: prefix because the runtime ships
// adapter errors verbatim.
func (e *gmpError) Error() string {
	prefix := "retryable:"
	if e.Fatal() {
		prefix = "fatal:"
	}
	return fmt.Sprintf("%s openvas: %s failed: status=%s %s", prefix, e.Command, e.Code, e.Text)
}

// Close closes the underlying connection.
func (c *gmpConn) Close() error { return c.conn.Close() }
