package logging

import (
	"os"
	"strings"
)

// Log levels. DEBUG and INFO are the everyday ones; SUCCESS is a terminal
// good-outcome line (job done, registration accepted) so a scan result is not
// lost among progress lines; WARN and ERROR mark things a human must read.
const (
	lvlDebug   = "DEBUG"
	lvlInfo    = "INFO"
	lvlSuccess = "SUCCESS"
	lvlWarn    = "WARN"
	lvlError   = "ERROR"
)

// ANSI SGR codes. ponytail: hand-rolled instead of a colour library — five
// codes are cheaper than a dependency in every connector image, and the format
// is frozen ANSI that no library will change under us.
const (
	cReset  = "0"
	cDim    = "2"
	cBright = "97"
	cRed    = "31"
	cGreen  = "32"
	cYellow = "33"
	cCyan   = "36"
)

// levelColor maps a level to its SGR colour.
func levelColor(level string) string {
	switch level {
	case lvlDebug:
		return cDim
	case lvlInfo:
		return cCyan
	case lvlSuccess:
		return cGreen
	case lvlWarn:
		return cYellow
	case lvlError:
		return cRed
	default:
		return cReset
	}
}

// paint wraps s in one or more SGR codes ("1;2" dims a bold prefix).
func paint(codes, s string) string {
	if !colorEnabled() {
		return s
	}
	return "\x1b[" + codes + "m" + s + "\x1b[" + cReset + "m"
}

// colorEnabled decides whether to emit ANSI colour, read per call so tests and
// operator env take effect without a package-level init:
//
//	OASM_LOG_COLOR=never|0|false   force off (also: NO_COLOR set to anything)
//	OASM_LOG_COLOR=always|1|true   force on (useful for a TTY-aware log viewer)
//	unset                          on only when stderr is a terminal
//
// The default matters: the Worker captures the container's stderr through
// Docker, where escape codes would be stored as noise in every persisted log
// line, so a non-TTY must stay plain.
func colorEnabled() bool {
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("OASM_LOG_COLOR"))); v != "" {
		switch v {
		case "never", "0", "false", "off", "no":
			return false
		case "always", "1", "true", "on", "yes":
			return true
		}
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	return isTerminal(os.Stderr)
}
