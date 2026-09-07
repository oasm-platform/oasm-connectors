package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	nucleiOutput "github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ss builds a stringslice.StringSlice the same way nuclei's YAML/JSON
// unmarshaller would (Value holds either a single string or a []string).
func ss(v any) stringslice.StringSlice { return stringslice.StringSlice{Value: v} }

// ref builds the *RawStringSlice shape model.Info.Reference carries.
func ref(v any) *stringslice.RawStringSlice {
	return &stringslice.RawStringSlice{StringSlice: ss(v)}
}

func TestResultEventToFinding(t *testing.T) {
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

	fullEvent := func() *nucleiOutput.ResultEvent {
		return &nucleiOutput.ResultEvent{
			TemplateID: "CVE-2021-1",
			Info: model.Info{
				Name:           "Real XSS",
				Tags:           ss("xss"),
				Reference:      ref("https://ref.example"),
				SeverityHolder: severity.Holder{Severity: severity.High},
				Remediation:    "patch it",
				Classification: &model.Classification{
					CVEID:       ss([]string{"CVE-2021-1"}),
					CWEID:       ss("CWE-79"),
					CVSSScore:   8.1,
					CVSSMetrics: "CVSS:3.1/AV:N/AC:L",
					EPSSScore:   0.00054,
				},
			},
			Matched:   "https://example.com",
			Host:      "example.com",
			IP:        "1.2.3.4",
			Timestamp: ts,
		}
	}

	tests := []struct {
		name    string
		event   func() *nucleiOutput.ResultEvent
		wantErr string // substring; "" = no error expected
		check   func(t *testing.T, f connector.Finding)
	}{
		{
			name:  "happy path maps every field",
			event: fullEvent,
			check: func(t *testing.T, f connector.Finding) {
				want := connector.Finding{
					Name:        "Real XSS",
					Severity:    "high",
					Tags:        []string{"xss"},
					References:  []string{"https://ref.example"},
					CVEID:       []string{"CVE-2021-1"},
					CWEID:       []string{"CWE-79"},
					CVSSScore:   8.1,
					CVSSMetrics: "CVSS:3.1/AV:N/AC:L",
					EPSSScore:   0.00054,
					Solution:    "patch it",
					MatchedAt:   "https://example.com",
					Host:        "example.com",
					IP:          "1.2.3.4",
				}
				got := f
				got.Timestamp = time.Time{}
				if !reflect.DeepEqual(got, want) {
					t.Errorf("finding mismatch:\ngot:  %+v\nwant: %+v", got, want)
				}
				if !f.Timestamp.Equal(ts) {
					t.Errorf("Timestamp = %v, want %v", f.Timestamp, ts)
				}
				if err := f.Validate(); err != nil {
					t.Errorf("mapped finding must validate: %v", err)
				}
			},
		},
		{
			name: "empty name falls back to template id",
			event: func() *nucleiOutput.ResultEvent {
				ev := fullEvent()
				ev.Info.Name = ""
				return ev
			},
			check: func(t *testing.T, f connector.Finding) {
				if f.Name != "CVE-2021-1" {
					t.Errorf("Name = %q, want template-id fallback CVE-2021-1", f.Name)
				}
			},
		},
		{
			name: "empty name and template id errors with no name",
			event: func() *nucleiOutput.ResultEvent {
				ev := fullEvent()
				ev.Info.Name = ""
				ev.TemplateID = ""
				return ev
			},
			wantErr: "no name",
		},
		{
			name: "unknown severity normalizes to info",
			event: func() *nucleiOutput.ResultEvent {
				ev := fullEvent()
				ev.Info.SeverityHolder = severity.Holder{Severity: severity.Unknown}
				return ev
			},
			check: func(t *testing.T, f connector.Finding) {
				if f.Severity != "info" {
					t.Errorf("Severity = %q, want info", f.Severity)
				}
			},
		},
		{
			name: "nil classification yields zero scores and empty ids",
			event: func() *nucleiOutput.ResultEvent {
				ev := fullEvent()
				ev.Info.Classification = nil
				return ev
			},
			check: func(t *testing.T, f connector.Finding) {
				if len(f.CVEID) != 0 || len(f.CWEID) != 0 {
					t.Errorf("ids = %v/%v, want empty", f.CVEID, f.CWEID)
				}
				if f.CVSSScore != 0 || f.CVSSMetrics != "" || f.EPSSScore != 0 {
					t.Errorf("scores = %v/%q/%v, want zero values", f.CVSSScore, f.CVSSMetrics, f.EPSSScore)
				}
			},
		},
		{
			name: "nil reference yields empty references",
			event: func() *nucleiOutput.ResultEvent {
				ev := fullEvent()
				ev.Info.Reference = nil
				return ev
			},
			check: func(t *testing.T, f connector.Finding) {
				if len(f.References) != 0 {
					t.Errorf("References = %v, want empty", f.References)
				}
			},
		},
		{
			name: "empty tags yield empty tags",
			event: func() *nucleiOutput.ResultEvent {
				ev := fullEvent()
				ev.Info.Tags = ss(nil)
				return ev
			},
			check: func(t *testing.T, f connector.Finding) {
				if len(f.Tags) != 0 {
					t.Errorf("Tags = %v, want empty", f.Tags)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f, err := resultEventToFinding(tc.event())
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tc.check(t, f)
		})
	}
}
