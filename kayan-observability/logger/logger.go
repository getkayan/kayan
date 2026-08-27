// Package logger provides structured logging for Kayan IAM.
//
// This package wraps Uber's zap logger to provide high-performance, structured
// logging with configurable log levels. It initializes a global logger instance
// for use throughout the Kayan application.
//
// # Configuration
//
// The log level is configured via the LOG_LEVEL environment variable or
// directly via InitLogger:
//
//	if err := logger.InitLogger("debug"); err != nil { // debug, info, warn, error
//	    // decide what a service does when its logger will not build
//	}
//
// # Usage
//
// Log is safe to use before InitLogger runs: until it is configured it is a
// no-op logger that discards what it is given. Logging during start-up, before
// configuration is read, therefore drops the line rather than crashing the
// process.
//
// After initialization, use the global Log variable:
//
//	logger.Log.Info("user logged in",
//	    zap.String("user_id", userID),
//	    zap.String("ip", clientIP),
//	)
//
//	logger.Log.Error("authentication failed",
//	    zap.Error(err),
//	    zap.String("strategy", "password"),
//	)
package logger

import (
	"fmt"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Log is the package logger.
//
// It starts as a no-op rather than nil. The documented usage is
// logger.Log.Info(...), and a nil global turns any log line written before
// InitLogger -- during start-up, or from a package initialised earlier than
// the logging configuration -- into a nil-pointer dereference that takes the
// process down. Discarding an early line is a far smaller problem than
// crashing over one.
var Log = zap.NewNop()

// InitLogger configures the package logger at the given level.
//
// Unrecognised levels fall back to info, which keeps a configuration typo from
// stopping a service that would otherwise run.
//
// It returns an error rather than panicking. A library that takes down the
// host process over its own configuration leaves the caller no way to fall
// back to a simpler logger, start in a degraded mode, or report the problem
// through a channel that still works -- and those are decisions only the
// application can make. On failure the previous logger is left in place, so
// logging keeps working.
func InitLogger(level string) error {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zap.InfoLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	built, err := cfg.Build()
	if err != nil {
		return fmt.Errorf("logger: build zap logger: %w", err)
	}
	Log = built
	return nil
}
