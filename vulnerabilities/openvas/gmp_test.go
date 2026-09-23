package main

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const (
	versionOK  = `<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>`
	versionBad = `<get_version_response status="400" status_text="Bad request"/>`
	authOK     = `<authenticate_response status="200" status_text="OK"/>`
)

type versionResponse struct {
	XMLName xml.Name `xml:"get_version_response"`
	Status  string   `xml:"status,attr"`
	Version string   `xml:"version"`
}

func dialFake(t *testing.T, f *fakeGMP) *gmpConn {
	t.Helper()
	c, err := dialGMP(context.Background(), f.config())
	if err != nil {
		t.Fatalf("dialGMP: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSend_HappyPathReusesConnection(t *testing.T) {
	f := newFakeGMP(t)
	f.script(versionOK, versionOK)
	c := dialFake(t, f)

	for i := 0; i < 2; i++ {
		var out versionResponse
		if err := c.send(context.Background(), "<get_version/>", &out); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		if out.Status != "200" || out.Version != "22.7" {
			t.Fatalf("send %d: got status=%q version=%q", i, out.Status, out.Version)
		}
	}
	if got := len(f.requests()); got != 2 {
		t.Fatalf("server saw %d requests, want 2 on one connection", got)
	}
}

func TestReadDocument_ExactSingleDocument(t *testing.T) {
	f := newFakeGMP(t)
	doc1 := versionOK
	doc2 := `<get_tasks_response status="200" status_text="OK"><task id="t1"/></get_tasks_response>`
	f.script(doc1 + doc2) // both documents delivered back-to-back
	c := dialFake(t, f)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := io.WriteString(c.conn, "<get_version/>\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw1, err := c.readDocument(ctx)
	if err != nil {
		t.Fatalf("readDocument 1: %v", err)
	}
	if string(raw1) != doc1 {
		t.Fatalf("raw1 = %q, want %q", raw1, doc1)
	}

	if _, err := io.WriteString(c.conn, "<get_tasks/>\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	raw2, err := c.readDocument(ctx)
	if err != nil {
		t.Fatalf("readDocument 2: %v", err)
	}
	if string(raw2) != doc2 {
		t.Fatalf("raw2 = %q, want %q", raw2, doc2)
	}
}

func TestReadDocument_Framing(t *testing.T) {
	pretty := "<get_version_response status=\"200\" status_text=\"OK\">\n  <version>22.7</version>\n</get_version_response>"
	cases := []struct {
		name    string
		payload string
		want    string
	}{
		{"trailing newline", versionOK + "\n", versionOK},
		{"pretty printed", pretty, pretty},
		{"pretty with trailing newline", pretty + "\n", pretty},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeGMP(t)
			f.script(tc.payload)
			c := dialFake(t, f)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := io.WriteString(c.conn, "<get_version/>\n"); err != nil {
				t.Fatalf("write: %v", err)
			}
			raw, err := c.readDocument(ctx)
			if err != nil {
				t.Fatalf("readDocument: %v", err)
			}
			if string(raw) != tc.want {
				t.Fatalf("raw = %q, want %q", raw, tc.want)
			}
		})
	}
}

func TestSend_Non2xxStatus(t *testing.T) {
	cases := []struct {
		name     string
		resp     string
		code     string
		prefix   string
		command  string
		wantText string
	}{
		{"400 fatal", versionBad, "400", "fatal:", "get_version_response", "Bad request"},
		{"503 retryable", `<get_version_response status="503" status_text="Service unavailable"/>`, "503", "retryable:", "get_version_response", "Service unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeGMP(t)
			f.script(tc.resp)
			c := dialFake(t, f)

			err := c.send(context.Background(), "<get_version/>", nil)
			if err == nil {
				t.Fatal("send returned nil, want error")
			}
			var ge *gmpError
			if !errors.As(err, &ge) {
				t.Fatalf("error = %T %v, want *gmpError", err, err)
			}
			if ge.Code != tc.code {
				t.Fatalf("code = %q, want %q", ge.Code, tc.code)
			}
			if ge.Command != tc.command {
				t.Fatalf("command = %q, want %q", ge.Command, tc.command)
			}
			if !strings.HasPrefix(err.Error(), tc.prefix) {
				t.Fatalf("Error() = %q, want prefix %q", err.Error(), tc.prefix)
			}
			if !strings.Contains(err.Error(), "status="+tc.code) {
				t.Fatalf("Error() = %q, want status=%s", err.Error(), tc.code)
			}
		})
	}
}

func TestGMPErrorClassification(t *testing.T) {
	fatal := &gmpError{Command: "get_version", Code: "400", Text: "Bad request"}
	if !fatal.Fatal() {
		t.Fatal("400 should be fatal")
	}
	if want := "fatal: openvas: get_version failed: status=400 Bad request"; fatal.Error() != want {
		t.Fatalf("Error() = %q, want %q", fatal.Error(), want)
	}

	retryable := &gmpError{Command: "get_tasks", Code: "500", Text: "Internal error"}
	if retryable.Fatal() {
		t.Fatal("500 should not be fatal")
	}
	if want := "retryable: openvas: get_tasks failed: status=500 Internal error"; retryable.Error() != want {
		t.Fatalf("Error() = %q, want %q", retryable.Error(), want)
	}
}

func TestAuthenticate_RequestShapeAndSuccess(t *testing.T) {
	f := newFakeGMP(t)
	f.script(authOK)
	c := dialFake(t, f)

	if err := c.authenticate(context.Background(), "admin", "secret"); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("server saw %d requests, want 1", len(reqs))
	}
	want := `<authenticate><credentials><username>admin</username><password>secret</password></credentials></authenticate>`
	if reqs[0] != want {
		t.Fatalf("request = %q, want %q", reqs[0], want)
	}
}

func TestAuthenticate_FailureIsFatal400(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<authenticate_response status="400" status_text="Authentication failed"/>`)
	c := dialFake(t, f)

	err := c.authenticate(context.Background(), "admin", "wrong")
	if err == nil {
		t.Fatal("authenticate returned nil, want error")
	}
	var ge *gmpError
	if !errors.As(err, &ge) || ge.Code != "400" {
		t.Fatalf("error = %v, want *gmpError code 400", err)
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Fatalf("Error() = %q, want fatal: prefix", err.Error())
	}
}

func TestSend_ServerClosesMidResponse(t *testing.T) {
	f := newFakeGMP(t)
	f.setHandler(func(string) (string, error) {
		return `<get_version_response status="200" status_text="OK"><version>22`, errors.New("boom")
	})
	c := dialFake(t, f)

	err := c.send(context.Background(), "<get_version/>", nil)
	if err == nil {
		t.Fatal("send returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "retryable:") {
		t.Fatalf("Error() = %q, want retryable: prefix", err.Error())
	}
	if !strings.Contains(err.Error(), "incomplete response") {
		t.Fatalf("Error() = %q, want incomplete response", err.Error())
	}
}

func TestSend_ContextAlreadyCancelled(t *testing.T) {
	f := newFakeGMP(t)
	f.script(versionOK)
	c := dialFake(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- c.send(ctx, "<get_version/>", nil) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("send returned nil, want error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if !strings.HasPrefix(err.Error(), "retryable:") {
			t.Fatalf("Error() = %q, want retryable: prefix", err.Error())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("send did not return promptly for a cancelled context")
	}
}

func TestSend_MalformedXMLIsFatal(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<get_version_response status="200"><version>22.7</get_version_response>`)
	c := dialFake(t, f)

	err := c.send(context.Background(), "<get_version/>", nil)
	if err == nil {
		t.Fatal("send returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Fatalf("Error() = %q, want fatal: prefix", err.Error())
	}
	var se *xml.SyntaxError
	if !errors.As(err, &se) {
		t.Fatalf("error = %T %v, want *xml.SyntaxError", err, err)
	}
}

func TestSend_CancelDuringRead_ReturnsContextCanceled(t *testing.T) {
	f := newFakeGMP(t)
	f.script() // server reads the request and never replies
	c := dialFake(t, f)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.send(ctx, "<get_version/>", nil) }()

	// Give send time to write and block in the read, then cancel mid-read.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if !strings.HasPrefix(err.Error(), "retryable:") {
			t.Fatalf("Error() = %q, want retryable: prefix", err.Error())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("send did not return within 5s of cancel")
	}
}

func TestDialGMP_Unreachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = dialGMP(ctx, &openvasConfig{Host: "127.0.0.1", Port: port, DisableTLSChecks: true})
	if err == nil {
		t.Fatal("dialGMP returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "retryable:") {
		t.Fatalf("Error() = %q, want retryable: prefix", err.Error())
	}
	if !strings.Contains(err.Error(), "dial") {
		t.Fatalf("Error() = %q, want dial in message", err.Error())
	}
}

func TestDialGMP_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := dialGMP(ctx, &openvasConfig{Host: "127.0.0.1", Port: 1, DisableTLSChecks: true})
	if err == nil {
		t.Fatal("dialGMP returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "retryable:") {
		t.Fatalf("Error() = %q, want retryable: prefix", err.Error())
	}
}
