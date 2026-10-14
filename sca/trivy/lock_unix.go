//go:build unix

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const lockPollInterval = 250 * time.Millisecond

// flockFile takes an flock on path: exclusive for the DB updater, shared for
// scanners. flock is per inode in the kernel, so it also coordinates the
// containers that share the cache volume. A zero wait blocks until ctx ends;
// otherwise errLockTimeout is returned once wait has passed.
func flockFile(ctx context.Context, path string, exclusive bool, wait time.Duration) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("trivy: open cache lock: %w", err)
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	var deadline <-chan time.Time
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		deadline = timer.C
	}
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("trivy: lock cache: %w", err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, ctx.Err()
		case <-deadline:
			_ = f.Close()
			return nil, errLockTimeout
		case <-time.After(lockPollInterval):
		}
	}
}
