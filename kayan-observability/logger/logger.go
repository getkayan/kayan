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
//	logger.InitLogger("debug") // Options: debug, info, warn, error
//
// # Usage
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
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Log *zap.Logger

func InitLogger(level string) {
	var zapLevel zapcore.Level
	if err := zapLevel.UnmarshalText([]byte(level)); err != nil {
		zapLevel = zap.InfoLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(zapLevel)
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	var err error
	Log, err = cfg.Build()
	if err != nil {
		panic(err)
	}
}
