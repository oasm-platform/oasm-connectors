package main

import (
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// niktoTuning is the meaning of one tuning code: the category name nikto
// documents in the header of program/databases/db_tests, plus the severity band
// that class of check implies.
//
// The severity column is a judgement, not data nikto publishes — nikto ships no
// score or rating anywhere. It is still far better grounded than keyword
// matching on the message, because it is keyed on nikto's own classification of
// what the check does rather than on how the sentence happens to be worded.
type niktoTuning struct {
	category string
	severity string
}

var niktoTunings = map[byte]niktoTuning{
	'0': {"File Upload", "high"},
	'1': {"Interesting File / Seen in logs", "low"},
	'2': {"Misconfiguration / Default File", "medium"},
	'3': {"Information Disclosure", "medium"},
	'4': {"Injection (XSS/Script/HTML)", "medium"},
	'5': {"Remote File Retrieval - Inside Web Root", "high"},
	'6': {"Denial of Service", "medium"},
	'7': {"Remote File Retrieval - Server Wide", "high"},
	'8': {"Command Execution / Remote Shell", "critical"},
	'9': {"SQL Injection", "high"},
	'a': {"Authentication Bypass", "high"},
	'b': {"Software Identification", "low"},
	'c': {"Remote source inclusion", "critical"},
	'd': {"WebService", "low"},
	'e': {"Administrative Console", "medium"},
	'f': {"XML Injection", "high"},
}

// dbEntry is one row of nikto's db_tests database.
type dbEntry struct {
	tuning string // field 3: one or more tuning codes, e.g. "23"
	refs   string // field 2: advisory references, space separated
	msg    string // field 7: the check description
}

// niktoDB is the parsed db_tests database, indexed by test id.
type niktoDB struct {
	entries map[string]dbEntry
}

var (
	dbOnce sync.Once
	dbVal  *niktoDB
)

// loadNiktoDB lazily reads nikto's test database and indexes it by id. It
// returns nil when the database cannot be located or parsed — the database
// only enriches findings, so a missing file must degrade to a plain scan
// rather than fail the job.
//
// The file is read from disk, never copied or embedded: it is distributed
// under a licence that permits use only as part of the Nikto package
// ("Database files are NOT licensed under the GPL ... for use exclusively with
// Nikto", program/COPYING). Reading it in place from the image satisfies that;
// redistributing it would not.
func loadNiktoDB() *niktoDB {
	dbOnce.Do(func() {
		for _, p := range dbPaths() {
			entries, err := parseNiktoDB(p)
			if err == nil && len(entries) > 0 {
				dbVal = &niktoDB{entries: entries}
				return
			}
		}
	})
	return dbVal
}

// dbPaths lists the candidate locations of db_tests, most specific first. The
// path is derived from NIKTO_BIN so a relocated nikto install keeps working.
func dbPaths() []string {
	var paths []string
	if bin := os.Getenv("NIKTO_BIN"); bin != "" {
		// <execdir>/nikto.pl -> <execdir>/databases/db_tests
		paths = append(paths, filepath.Join(filepath.Dir(bin), "databases", "db_tests"))
	}
	if dir := os.Getenv("NIKTO_DB_DIR"); dir != "" {
		paths = append(paths, filepath.Join(dir, "db_tests"))
	}
	// The layout shipped by the connector image (upstream Dockerfile puts
	// program/ at /opt/nikto and adds it to PATH).
	paths = append(paths, "/opt/nikto/databases/db_tests")
	return paths
}

// parseNiktoDB reads a db_tests file. Records are CSV: leading '#' comment
// lines are skipped, and encoding/csv handles the embedded commas and escaped
// quotes that appear in the message field (668 of 7240 rows contain commas
// inside quoted values, so a naive split would corrupt the columns).
func parseNiktoDB(path string) (map[string]dbEntry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	entries := make(map[string]dbEntry, 8000)
	r := csv.NewReader(f)
	// Fields per record vary (older rows carry trailing empties); the columns
	// we read are always the first seven, so only reject genuinely short rows.
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			// A malformed trailing record must not discard the whole database.
			if len(entries) > 0 {
				break
			}
			return nil, err
		}
		if len(rec) < 7 {
			continue
		}
		id := strings.TrimSpace(rec[0])
		if id == "" || strings.HasPrefix(id, "#") {
			continue
		}
		entries[id] = dbEntry{
			refs:   strings.TrimSpace(rec[1]),
			tuning: strings.TrimSpace(rec[2]),
			msg:    strings.TrimSpace(rec[6]),
		}
	}
	return entries, nil
}

// categoriesOf expands a tuning code string into its category names. A code
// like "23" means the check belongs to both Information Disclosure and
// Misconfiguration. Unrecognised codes are skipped.
func categoriesOf(tuning string) []string {
	if tuning == "" {
		return nil
	}
	var out []string
	seen := make(map[string]struct{}, len(tuning))
	for i := 0; i < len(tuning); i++ {
		t, ok := niktoTunings[tuning[i]]
		if !ok {
			continue
		}
		if _, dup := seen[t.category]; dup {
			continue
		}
		seen[t.category] = struct{}{}
		out = append(out, t.category)
	}
	return out
}

// severityFromTuning derives a severity band from the highest-severity tuning
// code attached to a check. A check tagged with several codes (e.g. "8a" =
// Command Execution + Authentication Bypass) takes the worst of them, since the
// most damaging thing it can do is what a reader needs to triage.
//
// ok is false when the tuning string carries no recognised code, which is the
// signal to fall back to message keywords.
func severityFromTuning(tuning string) (severity, category string, ok bool) {
	rank := map[string]int{"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	best := -1
	for i := 0; i < len(tuning); i++ {
		t, found := niktoTunings[tuning[i]]
		if !found {
			continue
		}
		if r := rank[t.severity]; r > best {
			best, severity, category, ok = r, t.severity, t.category, true
		}
	}
	return severity, category, ok
}
