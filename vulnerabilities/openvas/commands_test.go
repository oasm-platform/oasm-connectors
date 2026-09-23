// allow: SIZE_OK — plan T4 mandates a single commands_test.go holding every
// command's request-shape, response-parse, and failure cases together.
package main

import (
	"context"
	"encoding/xml"
	"errors"
	"strings"
	"testing"
)

// requestOf unmarshals the last recorded request into v. The XMLName tag on v
// makes a wrong root element (e.g. get_task instead of get_tasks) a hard
// failure, giving element/attribute-wise shape assertions per command.
func requestOf(t *testing.T, f *fakeGMP, v any) {
	t.Helper()
	reqs := f.requests()
	if len(reqs) == 0 {
		t.Fatal("server received no request")
	}
	raw := reqs[len(reqs)-1]
	if err := xml.Unmarshal([]byte(raw), v); err != nil {
		t.Fatalf("request shape: %v (raw: %s)", err, raw)
	}
}

func TestCreateTarget_HappyPath(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<create_target_response id="tgt-1" status="201" status_text="OK, resource created"/>`)
	c := dialFake(t, f)

	id, err := c.CreateTarget(context.Background(), "oasm-example.com", "192.168.1.0/24", "pl-1")
	if err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}
	if id != "tgt-1" {
		t.Fatalf("id = %q, want tgt-1", id)
	}

	var req struct {
		XMLName  xml.Name `xml:"create_target"`
		Name     string   `xml:"name"`
		Hosts    string   `xml:"hosts"`
		PortList *struct {
			ID string `xml:"id,attr"`
		} `xml:"port_list"`
	}
	requestOf(t, f, &req)
	if req.Name != "oasm-example.com" {
		t.Errorf("name = %q, want oasm-example.com", req.Name)
	}
	if req.Hosts != "192.168.1.0/24" {
		t.Errorf("hosts = %q, want 192.168.1.0/24", req.Hosts)
	}
	if req.PortList == nil || req.PortList.ID != "pl-1" {
		t.Errorf("port_list = %+v, want id=pl-1", req.PortList)
	}
}

func TestCreateTarget_OmitsPortListWhenEmpty(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<create_target_response id="tgt-2" status="201" status_text="OK, resource created"/>`)
	c := dialFake(t, f)

	if _, err := c.CreateTarget(context.Background(), "t", "10.0.0.1", ""); err != nil {
		t.Fatalf("CreateTarget: %v", err)
	}

	var req struct {
		XMLName  xml.Name `xml:"create_target"`
		PortList *struct {
			ID string `xml:"id,attr"`
		} `xml:"port_list"`
	}
	requestOf(t, f, &req)
	if req.PortList != nil {
		t.Errorf("port_list = %+v, want omitted when portListID is empty", req.PortList)
	}
}

func TestCreateTarget_MissingIDIsFatal(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<create_target_response status="201" status_text="OK, resource created"/>`)
	c := dialFake(t, f)

	_, err := c.CreateTarget(context.Background(), "t", "10.0.0.1", "")
	if err == nil {
		t.Fatal("CreateTarget returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Errorf("Error() = %q, want fatal: prefix", err.Error())
	}
	if !strings.Contains(err.Error(), "missing id") {
		t.Errorf("Error() = %q, want missing id", err.Error())
	}
}

func TestCreateTarget_Status403IsFatalGMPError(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<create_target_response status="403" status_text="Forbidden"/>`)
	c := dialFake(t, f)

	_, err := c.CreateTarget(context.Background(), "t", "10.0.0.1", "")
	if err == nil {
		t.Fatal("CreateTarget returned nil, want error")
	}
	var ge *gmpError
	if !errors.As(err, &ge) {
		t.Fatalf("error = %T %v, want *gmpError", err, err)
	}
	if ge.Code != "403" || ge.Command != "create_target_response" {
		t.Errorf("gmpError = %+v, want code=403 command=create_target_response", ge)
	}
	if !ge.Fatal() {
		t.Error("Fatal() = false, want true for 4xx")
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Errorf("Error() = %q, want fatal: prefix", err.Error())
	}
}

func TestCreateTask_HappyPath(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<create_task_response id="task-1" status="201" status_text="OK, resource created"/>`)
	c := dialFake(t, f)

	id, err := c.CreateTask(context.Background(), "oasm-scan", "cfg-1", "tgt-1", "scan-1")
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}
	if id != "task-1" {
		t.Fatalf("id = %q, want task-1", id)
	}

	var req struct {
		XMLName xml.Name `xml:"create_task"`
		Name    string   `xml:"name"`
		Config  struct {
			ID string `xml:"id,attr"`
		} `xml:"config"`
		Target struct {
			ID string `xml:"id,attr"`
		} `xml:"target"`
		Scanner struct {
			ID string `xml:"id,attr"`
		} `xml:"scanner"`
	}
	requestOf(t, f, &req)
	if req.Name != "oasm-scan" {
		t.Errorf("name = %q, want oasm-scan", req.Name)
	}
	if req.Config.ID != "cfg-1" {
		t.Errorf("config id = %q, want cfg-1", req.Config.ID)
	}
	if req.Target.ID != "tgt-1" {
		t.Errorf("target id = %q, want tgt-1", req.Target.ID)
	}
	if req.Scanner.ID != "scan-1" {
		t.Errorf("scanner id = %q, want scan-1", req.Scanner.ID)
	}
}

func TestCreateTask_MissingIDIsFatal(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<create_task_response status="201" status_text="OK, resource created"/>`)
	c := dialFake(t, f)

	_, err := c.CreateTask(context.Background(), "t", "c", "tg", "s")
	if err == nil {
		t.Fatal("CreateTask returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "fatal:") || !strings.Contains(err.Error(), "missing id") {
		t.Errorf("Error() = %q, want fatal: ... missing id", err.Error())
	}
}

func TestStartTask_ParsesReportIDFromChildElement(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<start_task_response status="202" status_text="OK, request submitted"><report_id>rep-1</report_id></start_task_response>`)
	c := dialFake(t, f)

	reportID, err := c.StartTask(context.Background(), "task-1")
	if err != nil {
		t.Fatalf("StartTask: %v", err)
	}
	if reportID != "rep-1" {
		t.Fatalf("reportID = %q, want rep-1 (must come from the report_id child element)", reportID)
	}

	var req struct {
		XMLName xml.Name `xml:"start_task"`
		TaskID  string   `xml:"task_id,attr"`
	}
	requestOf(t, f, &req)
	if req.TaskID != "task-1" {
		t.Errorf("task_id = %q, want task-1", req.TaskID)
	}
}

func TestStartTask_MissingReportIDIsFatal(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<start_task_response status="202" status_text="OK, request submitted"/>`)
	c := dialFake(t, f)

	_, err := c.StartTask(context.Background(), "task-1")
	if err == nil {
		t.Fatal("StartTask returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "fatal:") || !strings.Contains(err.Error(), "missing report_id") {
		t.Errorf("Error() = %q, want fatal: ... missing report_id", err.Error())
	}
}

func TestGetTaskStatus_UsesGetTasksAndReturnsStatus(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<get_tasks_response status="200" status_text="OK"><task id="task-1"><name>scan</name><status>Running</status><result_count>7</result_count></task></get_tasks_response>`)
	c := dialFake(t, f)

	status, err := c.GetTaskStatus(context.Background(), "task-1")
	if err != nil {
		t.Fatalf("GetTaskStatus: %v", err)
	}
	if status != "Running" {
		t.Fatalf("status = %q, want Running", status)
	}

	// GMP 22.7 has NO get_task command: the XMLName tag fails the test if the
	// builder ever emits <get_task> instead of <get_tasks task_id="...">.
	var req struct {
		XMLName xml.Name `xml:"get_tasks"`
		TaskID  string   `xml:"task_id,attr"`
	}
	requestOf(t, f, &req)
	if req.TaskID != "task-1" {
		t.Errorf("task_id = %q, want task-1", req.TaskID)
	}
}

func TestGetTaskStatus_InterruptedIsSurfaced(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<get_tasks_response status="200" status_text="OK"><task id="task-1"><status>Interrupted</status></task></get_tasks_response>`)
	c := dialFake(t, f)

	status, err := c.GetTaskStatus(context.Background(), "task-1")
	if err != nil {
		t.Fatalf("GetTaskStatus: %v", err)
	}
	if status != taskStatusInterrupted {
		t.Fatalf("status = %q, want Interrupted (terminal-failure, surfaced raw for T6)", status)
	}
}

func TestGetTaskStatus_NoTaskIsFatal(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<get_tasks_response status="200" status_text="OK"/>`)
	c := dialFake(t, f)

	_, err := c.GetTaskStatus(context.Background(), "task-1")
	if err == nil {
		t.Fatal("GetTaskStatus returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "fatal:") || !strings.Contains(err.Error(), "no task") {
		t.Errorf("Error() = %q, want fatal: ... no task", err.Error())
	}
}

const resultsOK = `<get_results_response status="200" status_text="OK">` +
	`<result id="res-1">` +
	`<name>CVE-2021-1234 on 443/tcp</name>` +
	`<host>10.0.0.5<asset asset_id="asset-9"/><hostname>web.example.com</hostname></host>` +
	`<port>443/tcp</port>` +
	`<nvt oid="1.3.6.1.4.1.25623.1.0.108098">` +
	`<name>SSL Certificate Info</name>` +
	`<family>Service detection</family>` +
	`<cvss_base>5.0</cvss_base>` +
	`<solution type="VendorFix">Upgrade the certificate</solution>` +
	`<severities score="5.0">` +
	`<severity type="cvss_base"><score>5.0</score><value>AV:N/AC:L/Au:N/C:P/I:N/A:N</value></severity>` +
	`<severity type="cvss_base_v2"><score>4.3</score><value>AV:N/AC:L/Au:N/C:P/I:N/A:N</value></severity>` +
	`</severities>` +
	`<refs>` +
	`<ref type="cve" id="CVE-2021-1234"/>` +
	`<ref type="cwe" id="CWE-295"/>` +
	`<ref type="url" id="https://example.com/advisory"/>` +
	`</refs>` +
	`</nvt>` +
	`<threat>Medium</threat>` +
	`<severity>5.0</severity>` +
	`<qod><value>87</value><type>remote_info</type></qod>` +
	`<description>Weak certificate.</description>` +
	`<creation_time>2024-05-23T09:22:12Z</creation_time>` +
	`<modification_time>2024-05-24T10:00:00Z</modification_time>` +
	`</result>` +
	`<result id="res-2">` +
	`<name>HTTP server info</name>` +
	`<host>10.0.0.6</host>` +
	`<port>80/tcp</port>` +
	`<nvt oid="1.3.6.1.4.1.25623.1.0.100001"><name>HTTP info</name></nvt>` +
	`<threat>Low</threat>` +
	`<severity>3.0</severity>` +
	`<qod><value>80</value></qod>` +
	`<description>Info.</description>` +
	`<creation_time>2024-01-01T00:00:00Z</creation_time>` +
	`<modification_time>2024-01-01T00:00:00Z</modification_time>` +
	`</result>` +
	`<filters id=""><term/></filters>` +
	`<sort><field><order>ascending</order></field></sort>` +
	`<results max="-1" start="1"/>` +
	`<result_count><filtered>42</filtered><page>42</page></result_count>` +
	`</get_results_response>`

func TestGetResults_ParsesResultsAndCount(t *testing.T) {
	f := newFakeGMP(t)
	f.script(resultsOK)
	c := dialFake(t, f)

	results, reported, countPresent, err := c.GetResults(context.Background(), "task-1")
	if err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("len(results) = %d, want 2", len(results))
	}
	if reported != 42 || !countPresent {
		t.Errorf("reported=%d countPresent=%v, want 42/true", reported, countPresent)
	}

	var req struct {
		XMLName xml.Name `xml:"get_results"`
		TaskID  string   `xml:"task_id,attr"`
		Filter  string   `xml:"filter,attr"`
	}
	requestOf(t, f, &req)
	if req.TaskID != "task-1" {
		t.Errorf("task_id = %q, want task-1", req.TaskID)
	}
	if req.Filter != "rows=-1 min_qod=0 levels=chmlg" {
		t.Errorf("filter = %q, want rows=-1 min_qod=0 levels=chmlg", req.Filter)
	}

	r := results[0]
	if r.ID != "res-1" || r.Name != "CVE-2021-1234 on 443/tcp" {
		t.Errorf("result identity = %q/%q", r.ID, r.Name)
	}
	if r.Host.IP != "10.0.0.5" {
		t.Errorf("host chardata = %q, want 10.0.0.5", r.Host.IP)
	}
	if r.Host.Hostname != "web.example.com" {
		t.Errorf("host hostname = %q, want web.example.com", r.Host.Hostname)
	}
	if r.Host.Asset.AssetID != "asset-9" {
		t.Errorf("host asset id = %q, want asset-9", r.Host.Asset.AssetID)
	}
	if r.Port != "443/tcp" {
		t.Errorf("port = %q, want 443/tcp", r.Port)
	}
	if r.Nvt.OID != "1.3.6.1.4.1.25623.1.0.108098" || r.Nvt.Name != "SSL Certificate Info" {
		t.Errorf("nvt = %+v", r.Nvt)
	}
	if r.Nvt.Family != "Service detection" || r.Nvt.CVSSBase != "5.0" {
		t.Errorf("nvt family/cvss = %q/%q", r.Nvt.Family, r.Nvt.CVSSBase)
	}
	if r.Nvt.Solution != "Upgrade the certificate" {
		t.Errorf("solution = %q", r.Nvt.Solution)
	}
	if len(r.Nvt.Severities.Severity) != 2 {
		t.Fatalf("severities = %+v, want 2", r.Nvt.Severities.Severity)
	}
	sev := r.Nvt.Severities.Severity[0]
	if sev.Type != "cvss_base" || sev.Score != "5.0" || sev.Value != "AV:N/AC:L/Au:N/C:P/I:N/A:N" {
		t.Errorf("severity[0] = %+v", sev)
	}
	if r.Nvt.Severities.Severity[1].Type != "cvss_base_v2" {
		t.Errorf("severity[1].type = %q, want cvss_base_v2", r.Nvt.Severities.Severity[1].Type)
	}
	wantRefs := []ResultRef{{Type: "cve", ID: "CVE-2021-1234"}, {Type: "cwe", ID: "CWE-295"}, {Type: "url", ID: "https://example.com/advisory"}}
	if len(r.Nvt.Refs.Ref) != 3 {
		t.Fatalf("refs = %+v, want 3", r.Nvt.Refs.Ref)
	}
	for i, w := range wantRefs {
		if r.Nvt.Refs.Ref[i] != w {
			t.Errorf("ref[%d] = %+v, want %+v", i, r.Nvt.Refs.Ref[i], w)
		}
	}
	if r.Threat != "Medium" || r.Severity != 5.0 {
		t.Errorf("threat/severity = %q/%v, want Medium/5.0", r.Threat, r.Severity)
	}
	if r.QOD.Value != 87 {
		t.Errorf("qod value = %d, want 87", r.QOD.Value)
	}
	if r.Description != "Weak certificate." {
		t.Errorf("description = %q", r.Description)
	}
	if r.CreationTime != "2024-05-23T09:22:12Z" || r.ModificationTime != "2024-05-24T10:00:00Z" {
		t.Errorf("times = %q/%q", r.CreationTime, r.ModificationTime)
	}

	// Second result: host is bare chardata (no hostname child).
	if results[1].Host.IP != "10.0.0.6" || results[1].Host.Hostname != "" {
		t.Errorf("results[1].Host = %+v, want ip-only host", results[1].Host)
	}
	if results[1].Severity != 3.0 || results[1].QOD.Value != 80 {
		t.Errorf("results[1] severity/qod = %v/%d", results[1].Severity, results[1].QOD.Value)
	}
}

func TestGetResults_WhenNoResultCount_ThenCountAbsent(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<get_results_response status="200" status_text="OK"><result id="res-1"><name>n</name><host>10.0.0.7</host><port>22/tcp</port><nvt oid="1.3.6"><name>x</name></nvt><threat>High</threat><severity>7.5</severity><qod><value>90</value></qod><description>d</description><creation_time>2024-01-01T00:00:00Z</creation_time><modification_time>2024-01-01T00:00:00Z</modification_time></result></get_results_response>`)
	c := dialFake(t, f)

	results, reported, countPresent, err := c.GetResults(context.Background(), "task-1")
	if err != nil {
		t.Fatalf("GetResults: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("len(results) = %d, want 1", len(results))
	}
	if countPresent || reported != 0 {
		t.Errorf("reported=%d countPresent=%v, want 0/false when result_count absent", reported, countPresent)
	}
}

func TestGetResults_UndecodableBodyIsFatalDecodeError(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<get_results_response status="200" status_text="OK"><result id="res-1"><severity>not-a-number</severity></result></get_results_response>`)
	c := dialFake(t, f)

	_, _, _, err := c.GetResults(context.Background(), "task-1")
	if err == nil {
		t.Fatal("GetResults returned nil, want error")
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Errorf("Error() = %q, want fatal: prefix", err.Error())
	}
	if !strings.Contains(err.Error(), "decode") {
		t.Errorf("Error() = %q, want decode error", err.Error())
	}
}

func TestStopTask_RequestShape(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<stop_task_response status="200" status_text="OK"/>`)
	c := dialFake(t, f)

	if err := c.StopTask(context.Background(), "task-1"); err != nil {
		t.Fatalf("StopTask: %v", err)
	}
	var req struct {
		XMLName xml.Name `xml:"stop_task"`
		TaskID  string   `xml:"task_id,attr"`
	}
	requestOf(t, f, &req)
	if req.TaskID != "task-1" {
		t.Errorf("task_id = %q, want task-1", req.TaskID)
	}
}

func TestDeleteTask_SendsUltimate(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<delete_task_response status="200" status_text="OK"/>`)
	c := dialFake(t, f)

	if err := c.DeleteTask(context.Background(), "task-1"); err != nil {
		t.Fatalf("DeleteTask: %v", err)
	}
	var req struct {
		XMLName  xml.Name `xml:"delete_task"`
		TaskID   string   `xml:"task_id,attr"`
		Ultimate string   `xml:"ultimate,attr"`
	}
	requestOf(t, f, &req)
	if req.TaskID != "task-1" {
		t.Errorf("task_id = %q, want task-1", req.TaskID)
	}
	if req.Ultimate != "1" {
		t.Errorf("ultimate = %q, want 1", req.Ultimate)
	}
}

func TestDeleteTarget_SendsUltimate(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<delete_target_response status="200" status_text="OK"/>`)
	c := dialFake(t, f)

	if err := c.DeleteTarget(context.Background(), "tgt-1"); err != nil {
		t.Fatalf("DeleteTarget: %v", err)
	}
	var req struct {
		XMLName  xml.Name `xml:"delete_target"`
		TargetID string   `xml:"target_id,attr"`
		Ultimate string   `xml:"ultimate,attr"`
	}
	requestOf(t, f, &req)
	if req.TargetID != "tgt-1" {
		t.Errorf("target_id = %q, want tgt-1", req.TargetID)
	}
	if req.Ultimate != "1" {
		t.Errorf("ultimate = %q, want 1", req.Ultimate)
	}
}

func TestDeleteTask_WhenStatus404_ThenFatalGMPError(t *testing.T) {
	f := newFakeGMP(t)
	f.script(`<delete_task_response status="404" status_text="Not found"/>`)
	c := dialFake(t, f)

	err := c.DeleteTask(context.Background(), "task-gone")
	if err == nil {
		t.Fatal("DeleteTask returned nil, want error")
	}
	var ge *gmpError
	if !errors.As(err, &ge) || ge.Code != "404" {
		t.Fatalf("error = %v, want *gmpError code 404", err)
	}
	if !strings.HasPrefix(err.Error(), "fatal:") {
		t.Errorf("Error() = %q, want fatal: prefix", err.Error())
	}
}
