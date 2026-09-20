//go:build windows

package main

import (
	"os"
	"os/exec"
)

// Windows has no process-group signal equivalent here; the connector only runs
// in a Linux container, so the fallback just kills the direct child.
func setProcessGroup(cmd *exec.Cmd) {}

func killProcessGroup(p *os.Process) error {
	if p == nil {
		return nil
	}
	return p.Kill()
}
