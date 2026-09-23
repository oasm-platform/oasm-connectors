// allow: SIZE_OK — plan T6 mandates a single adapter_test.go holding the
// happy path plus every failure case for the execute flow together.
package main

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// rootOf returns the root element name of one GMP request line ("authenticate",
// "get_tasks", ...), the dispatch key for the fake server handler.
func rootOf(req string) string {
	var probe struct{ XMLName xml.Name }
	if err := xml.Unmarshal([]byte(req), &probe); err != nil {
		return ""
	}
	return probe.XMLName.Local
}

// countRoot counts recorded requests whose root element is root.
func countRoot(f *fakeGMP, root string) int {
	n := 0
	for _, r := range f.requests() {
		if rootOf(r) == root {
			n++
		}
	}
	return n
}

// setConfig points the connector at host:port through OASM_CONFIG (the
// per-job profile path), isolating the process env first.
func setConfig(t *testing.T, host string, port int) {
	t.Helper()
	clearOpenVASEnv(t)
	raw, err := json.Marshal(map[string]any{
		"host":             host,
		"port":             port,
		"username":         "admin",
		"password":         "pw",
		"disableTlsChecks": true,
	})
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	t.Setenv("OASM_CONFIG", string(raw))
}

// setFakeConfig points the connector at the fake GMP server.
func setFakeConfig(t *testing.T, f *fakeGMP) {
	t.Helper()
	setConfig(t, "127.0.0.1", f.port)
}

// shortenPoll swaps pollInterval for a test and restores it on cleanup.
func shortenPoll(t *testing.T, d time.Duration) {
	t.Helper()
	old := pollInterval
	pollInterval = d
	t.Cleanup(func() { pollInterval = old })
}

// execute runs Execute synchronously, then drains out. Closing here (the
// runtime's job in production) also proves the adapter never closed it —
// a double close would panic.
func execute(ctx context.Context, target string) ([]connector.Finding, error) {
	out := make(chan connector.Finding, 64)
	err := (&OpenVASAdapter{}).Execute(ctx, map[string]any{"target": target}, out)
	close(out)
	var findings []connector.Finding
	for f := range out {
		findings = append(findings, f)
	}
	return findings, err
}

// taskStatusXML builds a single-task get_tasks response with the given status.
func taskStatusXML(status string) string {
	return `<get_tasks_response status="200" status_text="OK">` +
		`<task id="task-1"><name>scan</name><status>` + status + `</status>` +
		`<result_count>2</result_count></task></get_tasks_response>`
}

// adapterResultsOK is the happy-flow get_results document: 2 results whose
// result_count/filtered matches len(results), so the truncation policy
// performs exactly one fetch (no settle re-fetch, no backoff sleep).
const adapterResultsOK = `<get_results_response status="200" status_text="OK">` +
	`<result id="res-1">` +
	`<name>CVE-2021-1234 on 443/tcp</name>` +
	`<host>10.0.0.5<asset asset_id="asset-9"/><hostname>web.example.com</hostname></host>` +
	`<port>443/tcp</port>` +
	`<nvt oid="1.3.6.1.4.1.25623.1.0.108098">` +
	`<name>SSL Certificate Info</name><family>Service detection</family><cvss_base>5.0</cvss_base>` +
	`<solution type="VendorFix">Upgrade the certificate</solution>` +
	`<severities score="5.0"><severity type="cvss_base"><score>5.0</score><value>AV:N/AC:L/Au:N/C:P/I:N/A:N</value></severity></severities>` +
	`<refs><ref type="cve" id="CVE-2021-1234"/><ref type="cwe" id="CWE-295"/></refs>` +
	`</nvt>` +
	`<threat>Medium</threat><severity>5.0</severity><qod><value>87</value></qod>` +
	`<description>Weak certificate.</description>` +
	`<creation_time>2024-05-23T09:22:12Z</creation_time>` +
	`<modification_time>2024-05-24T10:00:00Z</modification_time>` +
	`</result>` +
	`<result id="res-2">` +
	`<name>HTTP server info</name>` +
	`<host>10.0.0.6</host><port>80/tcp</port>` +
	`<nvt oid="1.3.6.1.4.1.25623.1.0.100001"><name>HTTP info</name></nvt>` +
	`<threat>Low</threat><severity>3.0</severity><qod><value>80</value></qod>` +
	`<description>Info.</description>` +
	`<creation_time>2024-01-01T00:00:00Z</creation_time>` +
	`<modification_time>2024-01-01T00:00:00Z</modification_time>` +
	`</result>` +
	`<result_count><filtered>2</filtered><page>2</page></result_count>` +
	`</get_results_response>`

// fullFlowHandler dispatches on the request root element (robust to any poll
// count) and answers every command of a complete scan flow. getTasks builds
// the poll response per call: nil → always Running.
func fullFlowHandler(getTasks func(n int) string) func(string) (string, error) {
	polls := 0
	return func(req string) (string, error) {
		switch rootOf(req) {
		case "authenticate":
			return authOK, nil
		case "create_target":
			return `<create_target_response id="tgt-1" status="201" status_text="OK, resource created"/>`, nil
		case "create_task":
			return `<create_task_response id="task-1" status="201" status_text="OK, resource created"/>`, nil
		case "start_task":
			return `<start_task_response status="202" status_text="OK, request submitted"><report_id>rep-1</report_id></start_task_response>`, nil
		case "get_tasks":
			polls++
			if getTasks == nil {
				return taskStatusXML(taskStatusRunning), nil
			}
			return getTasks(polls), nil
		case "get_results":
			return adapterResultsOK, nil
		case "stop_task":
			return `<stop_task_response status="200" status_text="OK"/>`, nil
		case "delete_task":
			return `<delete_task_response status="200" status_text="OK"/>`, nil
		case "delete_target":
			return `<delete_target_response status="200" status_text="OK"/>`, nil
		default:
			return "", fmt.Errorf("unexpected GMP request: %s", req)
		}
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestAdapterValidateNoOp(t *testing.T) {
	a := OpenVASAdapter{}
	for _, in := range []map[string]any{nil, {}, {"target": "x"}, {"target": 42, "z": "y"}} {
		if err := a.Validate(context.Background(), in); err != nil {
			t.Errorf("Validate(%v) = %v, want nil", in, err)
		}
	}
}

// TestExecute_HappyPath: Given the fake GMP server scripting the full flow
// (auth → create target/task → start → Running → Done → 2 results → deletes),
// When Execute runs against it, Then 2 valid findings stream out and the task
// and target are each deleted exactly once.
func TestExecute_HappyPath(t *testing.T) {
	f := newFakeGMP(t)
	f.setHandler(fullFlowHandler(func(n int) string {
		if n == 1 {
			return taskStatusXML(taskStatusRunning)
		}
		return taskStatusXML(taskStatusDone)
	}))
	setFakeConfig(t, f)
	shortenPoll(t, time.Millisecond)

	findings, err := execute(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(findings), findings)
	}
	// Emit order is mapResults' deterministic sort by (host, port, oid, id):
	// "10.0.0.6" (ip host) sorts before "web.example.com" (hostname host).
	if findings[0].Name != "HTTP server info" {
		t.Errorf("findings[0].Name = %q, want HTTP server info", findings[0].Name)
	}
	if findings[1].Name != "CVE-2021-1234 on 443/tcp" {
		t.Errorf("findings[1].Name = %q, want CVE-2021-1234 on 443/tcp", findings[1].Name)
	}
	for i, fnd := range findings {
		if err := fnd.Validate(); err != nil {
			t.Errorf("findings[%d] failed Validate: %v (%+v)", i, err, fnd)
		}
	}

	// The full flow ran, with exactly one fetch (counts matched → no settle
	// re-fetch) and exactly one success-path delete of each resource.
	if n := countRoot(f, "get_tasks"); n < 2 {
		t.Errorf("get_tasks polls = %d, want >= 2 (Running then Done)", n)
	}
	if n := countRoot(f, "get_results"); n != 1 {
		t.Errorf("get_results = %d, want 1 (reported count matches)", n)
	}
	if n := countRoot(f, "delete_task"); n != 1 {
		t.Errorf("delete_task = %d, want 1", n)
	}
	if n := countRoot(f, "delete_target"); n != 1 {
		t.Errorf("delete_target = %d, want 1", n)
	}
	if n := countRoot(f, "stop_task"); n != 0 {
		t.Errorf("stop_task = %d, want 0 on the success path", n)
	}
}

// TestExecute_MissingTarget: Given inputs without a usable target, When
// Execute runs, Then it fails with fatal: target required before touching
// config or the network.
func TestExecute_MissingTarget(t *testing.T) {
	for _, raw := range []any{nil, "", "   ", "\t\n"} {
		in := map[string]any{}
		if raw != nil {
			in["target"] = raw
		}
		err := (&OpenVASAdapter{}).Execute(context.Background(), in, make(chan connector.Finding, 1))
		if err == nil || !strings.Contains(err.Error(), "target required") {
			t.Errorf("Execute(target=%v) err = %v, want 'target required'", raw, err)
			continue
		}
		if !strings.HasPrefix(err.Error(), "fatal:") {
			t.Errorf("Execute(target=%v) err = %q, want fatal: prefix", raw, err.Error())
		}
	}
}

// TestExecute_MissingHostInConfig: Given an OASM_CONFIG profile without a
// host, When Execute runs, Then the unprefixed loader error surfaces wrapped
// exactly once as fatal:.
func TestExecute_MissingHostInConfig(t *testing.T) {
	clearOpenVASEnv(t)
	t.Setenv("OASM_CONFIG", `{"username":"admin","password":"pw"}`)

	err := (&OpenVASAdapter{}).Execute(context.Background(), map[string]any{"target": "example.com"}, make(chan connector.Finding, 1))
	if err == nil || !strings.Contains(err.Error(), "host required") {
		t.Fatalf("err = %v, want host required", err)
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Errorf("Error() = %q, want fatal: prefix (single-owner wrap)", err.Error())
	}
	if strings.Contains(err.Error(), "fatal: fatal:") {
		t.Errorf("Error() = %q, want exactly one prefix", err.Error())
	}
}

// TestExecute_AuthFailed: Given the server rejects the login with
// status="400" status_text="Authentication failed", When Execute runs, Then
// the fatal gmpError surfaces as-is and no target is created.
func TestExecute_AuthFailed(t *testing.T) {
	f := newFakeGMP(t)
	f.setHandler(func(req string) (string, error) {
		if rootOf(req) == "authenticate" {
			return `<authenticate_response status="400" status_text="Authentication failed"/>`, nil
		}
		return "", fmt.Errorf("unexpected request after failed auth: %s", req)
	})
	setFakeConfig(t, f)

	_, err := execute(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "Authentication failed") {
		t.Fatalf("err = %v, want Authentication failed", err)
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Errorf("Error() = %q, want fatal: prefix from gmpError (returned as-is)", err.Error())
	}
	if strings.Contains(err.Error(), "fatal: fatal:") {
		t.Errorf("Error() = %q, want exactly one prefix (never re-wrap)", err.Error())
	}
	if n := countRoot(f, "create_target"); n != 0 {
		t.Errorf("create_target = %d, want 0 after failed auth", n)
	}
}

// TestExecute_TaskInterrupted_RetainsResources: Given the task ends with
// status Interrupted, When Execute polls it, Then a retryable error surfaces
// and NOTHING is deleted (retention-on-failure) — the cancel-cleanup defer
// must not fire on a non-cancellation failure.
func TestExecute_TaskInterrupted_RetainsResources(t *testing.T) {
	f := newFakeGMP(t)
	f.setHandler(fullFlowHandler(func(int) string {
		return taskStatusXML(taskStatusInterrupted)
	}))
	setFakeConfig(t, f)
	shortenPoll(t, time.Millisecond)

	_, err := execute(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "was interrupted") {
		t.Fatalf("err = %v, want 'was interrupted'", err)
	}
	if !strings.HasPrefix(err.Error(), "retryable:") {
		t.Errorf("Error() = %q, want retryable: prefix", err.Error())
	}
	if n := countRoot(f, "delete_task"); n != 0 {
		t.Errorf("delete_task = %d, want 0 (retention-on-failure)", n)
	}
	if n := countRoot(f, "delete_target"); n != 0 {
		t.Errorf("delete_target = %d, want 0 (retention-on-failure)", n)
	}
	if n := countRoot(f, "stop_task"); n != 0 {
		t.Errorf("stop_task = %d, want 0 (cancel-path only)", n)
	}
}

// TestExecute_TaskStoppedIsFatal: Given the task ends with status Stopped
// (administrative), When Execute polls it, Then a fatal error surfaces and
// nothing is deleted.
func TestExecute_TaskStoppedIsFatal(t *testing.T) {
	f := newFakeGMP(t)
	f.setHandler(fullFlowHandler(func(int) string {
		return taskStatusXML(taskStatusStopped)
	}))
	setFakeConfig(t, f)
	shortenPoll(t, time.Millisecond)

	_, err := execute(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "ended with status Stopped") {
		t.Fatalf("err = %v, want ended with status Stopped", err)
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Errorf("Error() = %q, want fatal: prefix", err.Error())
	}
	if n := countRoot(f, "delete_task"); n != 0 {
		t.Errorf("delete_task = %d, want 0 (retention-on-failure)", n)
	}
	if n := countRoot(f, "delete_target"); n != 0 {
		t.Errorf("delete_target = %d, want 0 (retention-on-failure)", n)
	}
}

// TestExecute_StopRequestedKeepsPolling: Given a transient Stop Requested
// status, When Execute polls, Then it keeps polling and completes when the
// task later reaches Done.
func TestExecute_StopRequestedKeepsPolling(t *testing.T) {
	f := newFakeGMP(t)
	f.setHandler(fullFlowHandler(func(n int) string {
		switch n {
		case 1:
			return taskStatusXML(taskStatusRunning)
		case 2:
			return taskStatusXML(taskStatusStopRequested)
		default:
			return taskStatusXML(taskStatusDone)
		}
	}))
	setFakeConfig(t, f)
	shortenPoll(t, time.Millisecond)

	findings, err := execute(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	if n := countRoot(f, "get_tasks"); n < 3 {
		t.Errorf("get_tasks polls = %d, want >= 3 (Stop Requested must keep polling)", n)
	}
}

// TestExecute_UnreachableAddress: Given no listener on the configured port,
// When Execute dials, Then the already-prefixed dial error surfaces as-is.
func TestExecute_UnreachableAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	setConfig(t, "127.0.0.1", port)

	_, err = execute(context.Background(), "example.com")
	if err == nil {
		t.Fatal("Execute returned nil, want dial error")
	}
	if !strings.HasPrefix(err.Error(), "retryable:") {
		t.Errorf("Error() = %q, want retryable: prefix (returned as-is)", err.Error())
	}
	if !strings.Contains(err.Error(), "dial") {
		t.Errorf("Error() = %q, want dial in message", err.Error())
	}
}

// TestExecute_CtxCancelMidPoll_CleansUp: Given a task that never finishes,
// When the context is cancelled mid-poll, Then Execute returns
// context.Canceled, the cancel-cleanup stop+delete+delete all run exactly
// once, and out stays empty.
func TestExecute_CtxCancelMidPoll_CleansUp(t *testing.T) {
	f := newFakeGMP(t)
	f.setHandler(fullFlowHandler(nil)) // always Running
	setFakeConfig(t, f)
	shortenPoll(t, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := make(chan connector.Finding, 16)
	done := make(chan error, 1)
	go func() {
		done <- (&OpenVASAdapter{}).Execute(ctx, map[string]any{"target": "example.com"}, out)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for countRoot(f, "get_tasks") < 1 {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for the first poll")
		}
		time.Sleep(2 * time.Millisecond)
	}
	// Let the first poll's exchange finish so cancel lands while the poll
	// loop waits on the ticker — no in-flight request, no abort race.
	time.Sleep(10 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		// Either the raw ctx.Err() from the poll select or the in-flight
		// request's retryable: openvas: cancelled: %w wrap is acceptable.
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Execute did not return after cancel")
	}

	if n := len(out); n != 0 {
		t.Errorf("emitted %d findings on cancel, want 0", n)
	}
	if n := countRoot(f, "stop_task"); n != 1 {
		t.Errorf("stop_task = %d, want 1 (cancel cleanup)", n)
	}
	if n := countRoot(f, "delete_task"); n != 1 {
		t.Errorf("delete_task = %d, want 1 (cancel cleanup)", n)
	}
	if n := countRoot(f, "delete_target"); n != 1 {
		t.Errorf("delete_target = %d, want 1 (cancel cleanup)", n)
	}
}

// TestExecute_CreateTargetMissingID: Given a create_target response without
// an id attribute, When Execute runs, Then the fatal missing-id error
// surfaces and NO task is created or started.
func TestExecute_CreateTargetMissingID(t *testing.T) {
	f := newFakeGMP(t)
	f.setHandler(func(req string) (string, error) {
		switch rootOf(req) {
		case "authenticate":
			return authOK, nil
		case "create_target":
			return `<create_target_response status="201" status_text="OK, resource created"/>`, nil
		default:
			return "", fmt.Errorf("unexpected request after missing id: %s", req)
		}
	})
	setFakeConfig(t, f)

	_, err := execute(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "missing id") {
		t.Fatalf("err = %v, want missing id", err)
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Errorf("Error() = %q, want fatal: prefix", err.Error())
	}
	if n := countRoot(f, "create_task"); n != 0 {
		t.Errorf("create_task = %d, want 0 when target id is missing", n)
	}
	if n := countRoot(f, "start_task"); n != 0 {
		t.Errorf("start_task = %d, want 0 when target id is missing", n)
	}
	if n := countRoot(f, "delete_target"); n != 0 {
		t.Errorf("delete_target = %d, want 0 (nothing created to delete)", n)
	}
}
