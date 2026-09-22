//go:build !windows

package logging

import "os"

// isTerminal reports whether f is a character device (a TTY/pty).
// ponytail: a mode check, not a real ioctl — enough to keep ANSI codes out of
// pipes and CI logs; swap in golang.org/x/term if a false positive shows up.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
