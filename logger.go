package GoogleIdTokenVerifier

import (
	"log"
)

var logger *log.Logger

// SetLogger changes the logger used for the verification messages
// By default, no log messages are emitted.
// To log to stderr, use
// `SetLogger(log.New(os.Stderr, "", log.LstdFlags))`
func SetLogger(l *log.Logger) {
	logger = l
}

func logf(fmt string, args ...interface{}) {
	if logger != nil {
		logger.Printf(fmt, args...)
	}
}
