package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The Trivy cache (vulnerability DB ~1.5 GB unpacked, Java DB when needed)
// cannot live in the container's /tmp: the worker mounts it as a 256 MB tmpfs
// and the root filesystem is read-only. The image declares the cache dir as
// an `oasm.persist` volume instead, which every container of the image
// shares. Trivy unpacks a DB update in place, so the containers coordinate
// through an flock on that volume: an update holds it exclusively, a scan
// holds it shared and never updates (--skip-db-update).

// errLockTimeout reports that the exclusive lock was not granted in time.
var errLockTimeout = errors.New("timed out waiting for the trivy cache lock")

const (
	lockFileName = ".oasm-trivy.lock"
	// updateLockWait bounds how long an update waits for running scans when
	// every needed DB is already cached: a DB a few hours old beats holding
	// the job until a long scan elsewhere releases its shared lock.
	updateLockWait = 2 * time.Minute
)

type lockFunc func(ctx context.Context, path string, exclusive bool, wait time.Duration) (unlock func(), err error)

// trivyDB is one database Trivy downloads into the cache dir.
type trivyDB struct {
	dir  string // subdirectory of the cache dir
	flag string // trivy flag that only refreshes it
	name string
}

var (
	vulnDB = trivyDB{dir: "db", flag: "--download-db-only", name: "vulnerability DB"}
	javaDB = trivyDB{dir: "java-db", flag: "--download-java-db-only", name: "Java DB"}
)

// defaultCacheDir is TRIVY_CACHE_DIR (set by the image to the persisted
// volume), else Trivy's own default.
func defaultCacheDir() string {
	if dir := os.Getenv("TRIVY_CACHE_DIR"); dir != "" {
		return dir
	}
	if dir, err := os.UserCacheDir(); err == nil {
		return filepath.Join(dir, "trivy")
	}
	return filepath.Join(os.TempDir(), "trivy")
}

func dbCached(cacheDir string, db trivyDB) bool {
	_, err := os.Stat(filepath.Join(cacheDir, db.dir, "metadata.json"))
	return err == nil
}

// javaArchiveExts are the files Trivy's jar analyzer opens — the only ones
// that need the Java DB (pom.xml and Gradle lockfiles use the main DB).
var javaArchiveExts = map[string]bool{".jar": true, ".war": true, ".ear": true, ".par": true}

func hasJavaArchives(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return nil
		case d.IsDir() && d.Name() == ".git":
			return filepath.SkipDir
		case !d.IsDir() && javaArchiveExts[strings.ToLower(filepath.Ext(d.Name()))]:
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

// updateDBs refreshes the databases the scan needs under the exclusive lock.
// Trivy only downloads a DB that is missing or past its update window, so a
// warm cache costs one metadata check. A failed refresh of a DB that is still
// cached is not fatal: the scan runs on the cached copy.
func updateDBs(ctx context.Context, cacheDir, scanDir string, java bool, run runFunc, lock lockFunc) error {
	dbs := []trivyDB{vulnDB}
	if java {
		dbs = append(dbs, javaDB)
	}
	var wait time.Duration
	if allCached(cacheDir, dbs) {
		wait = updateLockWait
	}
	unlock, err := lock(ctx, filepath.Join(cacheDir, lockFileName), true, wait)
	if errors.Is(err, errLockTimeout) {
		log.Printf("trivy: cache busy with running scans, using the cached databases")
		return nil
	}
	if err != nil {
		return err
	}
	defer unlock()

	// Download archives go next to the cache: the Java DB archive alone does
	// not fit the 256 MB /tmp. Holding the exclusive lock, whatever is left
	// here is from a killed download.
	tmp := filepath.Join(cacheDir, "tmp")
	_ = os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return fmt.Errorf("trivy: create download dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmp) }()

	for _, db := range dbs {
		args := append([]string{"fs", db.flag}, commonArgs(cacheDir)...)
		stderr, err := run(ctx, append(args, scanDir), []string{"TMPDIR=" + tmp})
		if err == nil {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if dbCached(cacheDir, db) {
			log.Printf("trivy: %s update failed, scanning with the cached copy: %v%s", db.name, err, formatStderr(stderr))
			continue
		}
		return fmt.Errorf("trivy: download %s: %w%s", db.name, err, formatStderr(stderr))
	}
	return nil
}

func allCached(cacheDir string, dbs []trivyDB) bool {
	for _, db := range dbs {
		if !dbCached(cacheDir, db) {
			return false
		}
	}
	return true
}

// commonArgs are the flags of every trivy invocation.
func commonArgs(cacheDir string) []string {
	return []string{
		"--cache-dir", cacheDir,
		"--no-progress",
		"--skip-version-check",
		"--disable-telemetry",
	}
}
