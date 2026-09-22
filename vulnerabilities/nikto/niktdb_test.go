package main

import "testing"

// The database file is not committed (its licence permits use only as part of
// the Nikto package), so tests that need it read it through NIKTO_DB_DIR. These
// tests are skipped when it is absent, which keeps `go test ./...` green in a
// plain source checkout while still pinning the parsing rules wherever the real
// database is available (CI with nikto installed, the connector image).

func TestParseNiktoDB_MissingFileIsNotFatal(t *testing.T) {
	if _, err := parseNiktoDB("testdata/does-not-exist"); err == nil {
		t.Fatal("expected an error for a missing database")
	}
	// loadNiktoDB must swallow that error and return nil rather than panic, so
	// a scan still runs when the database cannot be found.
	if db := loadNiktoDB(); db != nil {
		// Only assert the degradation contract, not the absence of the file.
		if len(db.entries) == 0 {
			t.Fatal("non-nil database with no entries")
		}
	}
}

func TestCategoriesOf(t *testing.T) {
	tests := []struct {
		tuning string
		want   []string
	}{
		{"", nil},
		{"2", []string{"Misconfiguration / Default File"}},
		{"23", []string{"Misconfiguration / Default File", "Information Disclosure"}},
		{"8", []string{"Command Execution / Remote Shell"}},
		{"a", []string{"Authentication Bypass"}},
		{"zz", nil},
		{"2z", []string{"Misconfiguration / Default File"}},
		{"22", []string{"Misconfiguration / Default File"}},
	}
	for _, tc := range tests {
		got := categoriesOf(tc.tuning)
		if len(got) != len(tc.want) {
			t.Errorf("categoriesOf(%q) = %v, want %v", tc.tuning, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("categoriesOf(%q) = %v, want %v", tc.tuning, got, tc.want)
				break
			}
		}
	}
}

func TestSeverityFromTuning(t *testing.T) {
	tests := []struct {
		tuning       string
		wantSeverity string
		wantCategory string
		wantOK       bool
	}{
		{"", "", "", false},
		{"2", "medium", "Misconfiguration / Default File", true},
		{"8", "critical", "Command Execution / Remote Shell", true},
		{"c", "critical", "Remote source inclusion", true},
		{"9", "high", "SQL Injection", true},
		{"b", "low", "Software Identification", true},
		// Multi-code checks take the worst band: "8a" is command execution
		// plus authentication bypass, and the command execution dominates.
		{"8a", "critical", "Command Execution / Remote Shell", true},
		{"1b", "low", "Interesting File / Seen in logs", true},
		{"13", "medium", "Information Disclosure", true},
		{"zz", "", "", false},
		// Unrecognised codes mixed with known ones still resolve.
		{"z9", "high", "SQL Injection", true},
	}
	for _, tc := range tests {
		sev, cat, ok := severityFromTuning(tc.tuning)
		if ok != tc.wantOK || sev != tc.wantSeverity || cat != tc.wantCategory {
			t.Errorf("severityFromTuning(%q) = (%q,%q,%v), want (%q,%q,%v)",
				tc.tuning, sev, cat, ok, tc.wantSeverity, tc.wantCategory, tc.wantOK)
		}
	}
}

func TestCvesIn(t *testing.T) {
	tests := []struct {
		refs []string
		want []string
	}{
		{nil, nil},
		{[]string{"CVE-2000-0709"}, []string{"CVE-2000-0709"}},
		// Stdout shape: the expanded advisory URL, not a bare token. This is
		// the case the old whole-token regex missed, leaving CVEID empty on
		// every real scan.
		{[]string{"https://nvd.nist.gov/vuln/detail/CVE-2000-0709"}, []string{"CVE-2000-0709"}},
		{[]string{"CVE-2001-1013 CVE-2002-1033"}, []string{"CVE-2001-1013", "CVE-2002-1033"}},
		{[]string{"https://x/CVE-2003-0001", "CVE-2003-0001"}, []string{"CVE-2003-0001"}},
		{[]string{"none"}, nil},
		{[]string{"MS99-013", "http://example.com/"}, nil},
	}
	for _, tc := range tests {
		got := cvesIn(tc.refs)
		if len(got) != len(tc.want) {
			t.Errorf("cvesIn(%v) = %v, want %v", tc.refs, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("cvesIn(%v) = %v, want %v", tc.refs, got, tc.want)
				break
			}
		}
	}
}

func TestDedupe(t *testing.T) {
	got := dedupe([]string{"a", "b", "a", "c", "b"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("dedupe = %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("dedupe = %v, want %v", got, want)
		}
	}
}
