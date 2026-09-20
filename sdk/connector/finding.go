package connector

import (
	"fmt"
	"time"
)

// Severities is the closed set of allowed finding severity values.
var Severities = []string{"info", "low", "medium", "high", "critical"}

// Finding is the canonical connector output item emitted by adapters.
// The contract is defined by the Finding message in sdk/proto/connector.proto.
type Finding struct {
	Name        string
	Severity    string
	Description string
	Tags        []string
	References  []string
	CVEID       []string
	CWEID       []string
	CVSSScore   float64
	CVSSMetrics string
	EPSSScore   float64
	Solution    string
	MatchedAt   string
	Host        string
	IP          string
	Timestamp   time.Time

	Synopsis         string
	Ports            []string
	Authors          []string
	VPRScore         float64
	BIDID            []string
	CEAID            []string
	IAVAID           []string
	PublicationDate  time.Time
	ModificationDate time.Time
	// Confidence is the scanner's confidence rating (e.g. Acunetix 80/95/100).
	Confidence float64
}

// Validate returns an error when the finding cannot be transported: a name is
// required and severity must be one of the Severities enum values.
func (f Finding) Validate() error {
	if f.Name == "" {
		return fmt.Errorf("name is required")
	}
	if !validSeverity(f.Severity) {
		return fmt.Errorf("severity %q not in enum [info low medium high critical]", f.Severity)
	}
	return nil
}

func validSeverity(s string) bool {
	for _, v := range Severities {
		if s == v {
			return true
		}
	}
	return false
}
