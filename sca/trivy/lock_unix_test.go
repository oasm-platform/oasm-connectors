//go:build unix

package main

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestFlockSharedAndExclusive(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), lockFileName)

	shared1, err := flockFile(ctx, path, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	shared2, err := flockFile(ctx, path, false, time.Second)
	if err != nil {
		t.Fatalf("two scans must share the lock: %v", err)
	}
	if _, err := flockFile(ctx, path, true, 300*time.Millisecond); !errors.Is(err, errLockTimeout) {
		t.Fatalf("an update must wait for running scans, got %v", err)
	}
	shared1()
	shared2()

	exclusive, err := flockFile(ctx, path, true, time.Second)
	if err != nil {
		t.Fatalf("exclusive lock once scans are done: %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := flockFile(cancelled, path, false, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("a scan waiting for an update must honour ctx, got %v", err)
	}
	exclusive()
}
