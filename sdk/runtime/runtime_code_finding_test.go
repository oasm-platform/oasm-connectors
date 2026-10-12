package runtime

import (
	"testing"

	"github.com/oasm-platform/oasm-connectors/sdk/connector"
)

// TestToProtoFindingCarriesCodeFields guards the code-finding fields on the
// wire: a repository scanner's file/line/commit/package/fingerprint must reach
// the worker unchanged.
func TestToProtoFindingCarriesCodeFields(t *testing.T) {
	got := toProtoFinding(connector.Finding{
		Name:             "aws-access-key",
		Severity:         "high",
		FilePath:         "config/prod.env",
		LineStart:        12,
		LineEnd:          12,
		Commit:           "0123456789abcdef0123456789abcdef01234567",
		PackageName:      "lodash",
		InstalledVersion: "4.17.15",
		FixedVersion:     "4.17.21",
		Fingerprint:      "aws-access-key:config/prod.env:12",
	})

	if got.GetFilePath() != "config/prod.env" ||
		got.GetLineStart() != 12 ||
		got.GetLineEnd() != 12 ||
		got.GetCommit() != "0123456789abcdef0123456789abcdef01234567" ||
		got.GetPackageName() != "lodash" ||
		got.GetInstalledVersion() != "4.17.15" ||
		got.GetFixedVersion() != "4.17.21" ||
		got.GetFingerprint() != "aws-access-key:config/prod.env:12" {
		t.Fatalf("code fields lost in mapping: %+v", got)
	}
}

// TestToProtoFindingHostFindingLeavesCodeFieldsEmpty keeps host scanners'
// wire format unchanged.
func TestToProtoFindingHostFindingLeavesCodeFieldsEmpty(t *testing.T) {
	got := toProtoFinding(connector.Finding{Name: "xss", Severity: "medium", Host: "example.com"})
	if got.GetFilePath() != "" || got.GetLineStart() != 0 || got.GetFingerprint() != "" {
		t.Fatalf("host finding gained code fields: %+v", got)
	}
}
