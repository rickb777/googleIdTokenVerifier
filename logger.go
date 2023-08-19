package googleIdTokenVerifier

import (
	"fmt"
	"log"
	"log/slog"
	"strings"
)

var Verbose = false
var logger *log.Logger
var slogger *slog.Logger

// SetLogger changes the logger used for the verification messages
// By default, no log messages are emitted.
// To log to stderr, use
// `SetLogger(log.New(os.Stderr, "", log.LstdFlags))`
func SetLogger(l *log.Logger) {
	logger = l
}

// SetSlogger changes the logger used for the verification messages
// By default, no log messages are emitted.
// This takes priority over SetLogger
func SetSlogger(l *slog.Logger) {
	slogger = l
}

func logf(msg string, args ...any) {
	if slogger != nil {
		slogger.Debug(msg, args...)
	} else {
		b := &strings.Builder{}
		b.WriteString(msg)
		b.WriteString(": ")
		comma := ""
		for i := 1; i < len(args); i += 2 {
			fmt.Fprintf(b, "%s%s: %v", comma, args[i-1], args[i])
			comma = ", "
		}
		b.WriteString("\n")
		if logger != nil {
			logger.Printf(b.String())
		} else if Verbose {
			log.Printf(b.String())
		}
	}
}
