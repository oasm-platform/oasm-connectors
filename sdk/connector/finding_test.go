package connector

import (
	"strings"
	"testing"
	"time"
)

func TestFindingValidate(t *testing.T) {
	tests := []struct {
		name    string
		finding Finding
		wantErr string
	}{
		{
			name:    "valid finding passes",
			finding: Finding{Name: "CVE-2023-1234", Severity: "high", Timestamp: time.Now()},
			wantErr: "",
		},
		{
			name: "empty name fails",
			finding: Finding{
				Severity:  "low",
				Timestamp: time.Now(),
			},
			wantErr: "name is required",
		},
		{
			name: "missing severity fails",
			finding: Finding{
				Name:      "test-finding",
				Timestamp: time.Now(),
			},
			wantErr: "severity",
		},
		{
			name: "severity not in enum fails",
			finding: Finding{
				Name:      "test-finding",
				Severity:  "catastrophic",
				Timestamp: time.Now(),
			},
			wantErr: "severity",
		},
		{
			name: "uppercase severity fails",
			finding: Finding{
				Name:      "test-finding",
				Severity:  "HIGH",
				Timestamp: time.Now(),
			},
			wantErr: "severity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.finding.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() returned unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() error = %q, want it to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestFindingValidateAllSeverities(t *testing.T) {
	for _, sev := range []string{"info", "low", "medium", "high", "critical"} {
		f := Finding{Name: "f", Severity: sev}
		if err := f.Validate(); err != nil {
			t.Errorf("severity %q should be valid, got: %v", sev, err)
		}
	}
}
