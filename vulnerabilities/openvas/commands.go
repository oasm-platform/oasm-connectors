package main

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
)

// Request XML for every command is built with typed encoding/xml structs —
// the same style authenticate uses in gmp.go. This is the ONE request style
// for the whole layer; there are no literal string builders. xml.Marshal emits
// <x></x> rather than the self-closing <x/> — the two are identical XML and
// gvmd accepts both, which is why tests assert element/attribute-wise after
// unmarshalling rather than byte-for-byte. Responses decode into typed structs
// via gmpConn.send, which validates the envelope status.
//
// Every method takes ctx first: send applies its deadline and cancellation
// watcher to the connection, and the adapter's cancel-cleanup passes a
// detached context so cleanup survives a cancelled parent.
//
// Shapes verified against the GMP 22.7 reference
// (https://docs.greenbone.net/API/GMP/gmp-22.7.html) and python-gvm GMPv227
// (https://greenbone.github.io/python-gvm/api/gmpv227.html); per-command
// citations live in .omo/notepads/openvas-connector/learnings.md.

// resultsFilter is the get_results filter attribute. rows=-1 returns all rows
// (the GMP 22.7 examples use filter="first=1, rows=-1" and echo
// <results max="-1" start="1"/>). min_qod=0 and levels override the server's
// default result filter (commonly min_qod=70 levels=hml, which would silently
// drop every result below QoD 70 and all Low/Log/Critical findings).
// levels letters per GMP 22.7 §5.13: c=critical, h=high, m=medium, l=low,
// g=log, f=false positive.
// ponytail: levels=chmlg excludes f (false positive) — FP results are noise
// for the platform finding stream; append f to the filter if FP review is
// ever required.
const resultsFilter = "rows=-1 min_qod=0 levels=chmlg"

// GMP 22.7 task_status enum (§5.23) — the complete set, in spec order; there
// is no "Container" value. Terminal classification for the T6 poll loop:
// taskStatusDone is the only terminal-success; taskStatusInterrupted,
// taskStatusStopped and taskStatusDeleteRequested are terminal-failure;
// taskStatusStopRequested is transient (normally transitions to Stopped) and
// must not short-circuit polling — keep polling on every other value.
const (
	taskStatusDeleteRequested = "Delete Requested"
	taskStatusDone            = "Done"
	taskStatusNew             = "New"
	taskStatusProcessing      = "Processing"
	taskStatusRequested       = "Requested"
	taskStatusRunning         = "Running"
	taskStatusStopRequested   = "Stop Requested"
	taskStatusStopped         = "Stopped"
	taskStatusInterrupted     = "Interrupted"
)

// idRef is the shared <x id="UUID"/> reference element (config, target,
// scanner, port_list).
type idRef struct {
	ID string `xml:"id,attr"`
}

// Request shapes (GMP 22.7 §7.20/7.21/7.114/7.79/7.71/7.115/7.44/7.43).

type createTargetRequest struct {
	XMLName  xml.Name `xml:"create_target"`
	Name     string   `xml:"name"`
	Hosts    string   `xml:"hosts"`
	PortList *idRef   `xml:"port_list,omitempty"`
}

type createTaskRequest struct {
	XMLName xml.Name `xml:"create_task"`
	Name    string   `xml:"name"`
	Config  idRef    `xml:"config"`
	Target  idRef    `xml:"target"`
	Scanner idRef    `xml:"scanner"`
}

type startTaskRequest struct {
	XMLName xml.Name `xml:"start_task"`
	TaskID  string   `xml:"task_id,attr"`
}

// getTasksRequest is the single-task poll form: GMP 22.7 has NO get_task
// command — the task_id attribute on get_tasks selects exactly one task.
type getTasksRequest struct {
	XMLName xml.Name `xml:"get_tasks"`
	TaskID  string   `xml:"task_id,attr"`
}

type getResultsRequest struct {
	XMLName xml.Name `xml:"get_results"`
	TaskID  string   `xml:"task_id,attr"`
	Filter  string   `xml:"filter,attr"`
}

type stopTaskRequest struct {
	XMLName xml.Name `xml:"stop_task"`
	TaskID  string   `xml:"task_id,attr"`
}

type deleteTaskRequest struct {
	XMLName  xml.Name `xml:"delete_task"`
	TaskID   string   `xml:"task_id,attr"`
	Ultimate string   `xml:"ultimate,attr"`
}

type deleteTargetRequest struct {
	XMLName  xml.Name `xml:"delete_target"`
	TargetID string   `xml:"target_id,attr"`
	Ultimate string   `xml:"ultimate,attr"`
}

// Response shapes. Envelope status/status_text are validated by send; only
// command-specific payloads are decoded here.

type createTargetResponse struct {
	XMLName xml.Name `xml:"create_target_response"`
	ID      string   `xml:"id,attr"`
}

type createTaskResponse struct {
	XMLName xml.Name `xml:"create_task_response"`
	ID      string   `xml:"id,attr"`
}

// startTaskResponse: the report id is a CHILD ELEMENT of the response, never
// an attribute (GMP 22.7 §7.114 RNC start_task_response_report_id).
type startTaskResponse struct {
	XMLName  xml.Name `xml:"start_task_response"`
	ReportID string   `xml:"report_id"`
}

// getTasksResponse: each <task> carries <status> (task_status enum) and
// <result_count> — the task's TOTAL result count as plain text, a sibling of
// <status> (distinct from get_results' result_count/filtered|page structure).
type getTasksResponse struct {
	XMLName xml.Name       `xml:"get_tasks_response"`
	Tasks   []gmpTaskState `xml:"task"`
}

type gmpTaskState struct {
	Status      string `xml:"status"`
	ResultCount string `xml:"result_count"`
}

type getResultsResponse struct {
	XMLName     xml.Name     `xml:"get_results_response"`
	Results     []Result     `xml:"result"`
	ResultCount *gmpCountBox `xml:"result_count"`
}

// gmpCountBox decodes the optional <result_count><filtered>N</filtered>
// <page>P</page></result_count> element; a nil pointer means absent.
type gmpCountBox struct {
	Filtered int `xml:"filtered"`
	Page     int `xml:"page"`
}

// Result is one <result> from get_results — the shape T5 maps to findings
// (GMP 22.7 §6.14 result element).
type Result struct {
	ID               string     `xml:"id,attr"`
	Name             string     `xml:"name"`
	Host             ResultHost `xml:"host"`
	Port             string     `xml:"port"`
	Nvt              ResultNvt  `xml:"nvt"`
	Threat           string     `xml:"threat"`
	Severity         float64    `xml:"severity"`
	QOD              ResultQOD  `xml:"qod"`
	Description      string     `xml:"description"`
	CreationTime     string     `xml:"creation_time"`
	ModificationTime string     `xml:"modification_time"`
}

// ResultHost is <host>: chardata holds the IP, <hostname> is a DIRECT child,
// and <asset asset_id> is a sibling carrying only the asset id (it is not the
// hostname source).
type ResultHost struct {
	IP       string `xml:",chardata"`
	Hostname string `xml:"hostname"`
	Asset    struct {
		AssetID string `xml:"asset_id,attr"`
	} `xml:"asset"`
}

// ResultNvt is the result's <nvt> sub-element.
type ResultNvt struct {
	OID        string           `xml:"oid,attr"`
	Name       string           `xml:"name"`
	Family     string           `xml:"family"`
	CVSSBase   string           `xml:"cvss_base"`
	Solution   string           `xml:"solution"`
	Severities ResultSeverities `xml:"severities"`
	Refs       ResultRefs       `xml:"refs"`
}

// ResultSeverities is <severities> holding child <severity> entries (the
// severities @score attribute is not needed by T5 and is not decoded).
type ResultSeverities struct {
	Severity []ResultSeverity `xml:"severity"`
}

// ResultSeverity is one <severity type="cvss_base|cvss_base_v2"> with
// <score/> and <value/> (CVSS vector) children. Score stays a string so an
// absent score ("") is distinguishable from a legitimate 0.0.
type ResultSeverity struct {
	Type  string `xml:"type,attr"`
	Score string `xml:"score"`
	Value string `xml:"value"`
}

type ResultRefs struct {
	Ref []ResultRef `xml:"ref"`
}

// ResultRef is <ref type="cve|cwe|url" id="..."/>.
type ResultRef struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}

// ResultQOD is <qod>; RNC: <value> is an integer, <type> is not needed by T5.
type ResultQOD struct {
	Value int `xml:"value"`
}

// sendCommand marshals a typed request and sends it as one GMP command,
// decoding the response into out when non-nil. A marshal failure on these
// fixed structs is a programming error, so it is reported fatal.
func (c *gmpConn) sendCommand(ctx context.Context, req, out any) error {
	raw, err := xml.Marshal(req)
	if err != nil {
		return fmt.Errorf("fatal: openvas: build GMP request: %w", err)
	}
	return c.send(ctx, string(raw), out)
}

// CreateTarget creates a scan target and returns its UUID from the response
// id attribute. portListID is sent as <port_list id> only when non-empty;
// empty means gvmd applies its own default port list.
func (c *gmpConn) CreateTarget(ctx context.Context, name, hosts, portListID string) (string, error) {
	req := createTargetRequest{Name: name, Hosts: hosts}
	if portListID != "" {
		req.PortList = &idRef{ID: portListID}
	}
	var out createTargetResponse
	if err := c.sendCommand(ctx, req, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		// Retrying cannot conjure an id the server withheld — fail loud.
		return "", errors.New("fatal: openvas: create_target response missing id")
	}
	return out.ID, nil
}

// CreateTask creates a scan task bound to config/target/scanner and returns
// its UUID from the response id attribute.
func (c *gmpConn) CreateTask(ctx context.Context, name, configID, targetID, scannerID string) (string, error) {
	req := createTaskRequest{
		Name:    name,
		Config:  idRef{ID: configID},
		Target:  idRef{ID: targetID},
		Scanner: idRef{ID: scannerID},
	}
	var out createTaskResponse
	if err := c.sendCommand(ctx, req, &out); err != nil {
		return "", err
	}
	if out.ID == "" {
		return "", errors.New("fatal: openvas: create_task response missing id")
	}
	return out.ID, nil
}

// StartTask starts a task and returns the report id from the response's
// <report_id> child element (not an attribute).
func (c *gmpConn) StartTask(ctx context.Context, taskID string) (string, error) {
	var out startTaskResponse
	if err := c.sendCommand(ctx, startTaskRequest{TaskID: taskID}, &out); err != nil {
		return "", err
	}
	if out.ReportID == "" {
		return "", errors.New("fatal: openvas: start_task response missing report_id")
	}
	return out.ReportID, nil
}

// GetTaskStatus returns the raw <status> string of one task, fetched with
// <get_tasks task_id="..."> (GMP 22.7 has no get_task command). The same
// <task> element carries <result_count> — the task's total result count as
// plain text, a direct sibling of <status> — decoded into
// getTasksResponse.Tasks[i].ResultCount; GetResults' reported count
// (result_count/filtered) is the per-fetch count T5 compares against.
// Terminal handling belongs to T6: only taskStatusDone is terminal-success —
// see the taskStatus constants for the full classification.
func (c *gmpConn) GetTaskStatus(ctx context.Context, taskID string) (string, error) {
	var out getTasksResponse
	if err := c.sendCommand(ctx, getTasksRequest{TaskID: taskID}, &out); err != nil {
		return "", err
	}
	if len(out.Tasks) == 0 {
		// A 200 with no task means the task vanished (e.g. concurrent
		// delete) — polling it can never succeed.
		return "", errors.New("fatal: openvas: get_tasks response contained no task")
	}
	status := out.Tasks[0].Status
	if status == "" {
		return "", fmt.Errorf("fatal: openvas: get_tasks response missing status for task %s", taskID)
	}
	return status, nil
}

// GetResults fetches every result of a task (resultsFilter: all rows, no
// QoD/severity floor) and reports the optional result_count/filtered as
// reported with countPresent=true. It returns transport/protocol errors only —
// truncation policy (re-fetch when reported exceeds len(results)) belongs to
// collectFindings in T5.
func (c *gmpConn) GetResults(ctx context.Context, taskID string) (results []Result, reported int, countPresent bool, err error) {
	req := getResultsRequest{TaskID: taskID, Filter: resultsFilter}
	var out getResultsResponse
	if err := c.sendCommand(ctx, req, &out); err != nil {
		return nil, 0, false, err
	}
	if out.ResultCount == nil {
		return out.Results, 0, false, nil
	}
	return out.Results, out.ResultCount.Filtered, true, nil
}

// StopTask asks gvmd to stop a running task (best-effort on the cancel path).
func (c *gmpConn) StopTask(ctx context.Context, taskID string) error {
	return c.sendCommand(ctx, stopTaskRequest{TaskID: taskID}, nil)
}

// DeleteTask removes a task entirely (ultimate="1": trash bypass).
func (c *gmpConn) DeleteTask(ctx context.Context, taskID string) error {
	return c.sendCommand(ctx, deleteTaskRequest{TaskID: taskID, Ultimate: "1"}, nil)
}

// DeleteTarget removes a target entirely (ultimate="1": trash bypass).
// Only ever call it with a target this connector created.
func (c *gmpConn) DeleteTarget(ctx context.Context, targetID string) error {
	return c.sendCommand(ctx, deleteTargetRequest{TargetID: targetID, Ultimate: "1"}, nil)
}
