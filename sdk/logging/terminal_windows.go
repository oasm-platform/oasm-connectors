//go:build windows

package logging

import (
	"os"
	"syscall"
)

// Console handle type returned by GetFileType for a character device.
const fileTypeChar = 2

var (
	kernel32        = syscall.NewLazyDLL("kernel32.dll")
	procGetFileType = kernel32.NewProc("GetFileType")
)

// isTerminal reports whether f is a Windows console handle. Windows does not
// set os.ModeCharDevice for console handles, so the unix mode check would always
// answer "not a terminal"; GetFileType is the cheap equivalent. An unknown
// handle type (0) reads as "not a terminal", the safe direction for log files.
func isTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	r, _, _ := procGetFileType.Call(f.Fd())
	return uint32(r) == fileTypeChar
}
