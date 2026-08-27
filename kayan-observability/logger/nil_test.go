package logger

import (
	"testing"
)

// TestLogIsUsableBeforeInit covers a nil-pointer dereference the package
// documentation walked callers straight into.
//
// Log was a package-global left nil until InitLogger ran, while the package
// doc showed `logger.Log.Info(...)` as the usage. A caller who followed it
// before initialising -- or whose initialisation happened later in start-up
// than their first log line -- crashed the process.
//
// The zero value is now a working no-op logger, so logging before
// configuration discards the line instead of taking the service down.
func TestLogIsUsableBeforeInit(t *testing.T) {
	if Log == nil {
		t.Fatal("Log is nil before InitLogger; logging during start-up panics")
	}
	// Must not panic.
	Log.Info("a line logged before the logger was configured")
	Log.Error("and an error")
	Log.Sync() //nolint:errcheck // a no-op logger has nothing to flush
}

// TestInitLoggerReturnsAnError covers the other half: InitLogger panicked when
// the logger could not be built. A library that takes the host process down
// over its own configuration leaves the caller no way to fall back, degrade,
// or report -- decisions only the application can make.
func TestInitLoggerReturnsAnError(t *testing.T) {
	if err := InitLogger("info"); err != nil {
		t.Fatalf("InitLogger(info): %v", err)
	}
	if Log == nil {
		t.Error("InitLogger returned nil error but left Log nil")
	}
}

// TestInitLoggerAcceptsAnUnknownLevel keeps the documented tolerance: an
// unrecognised level falls back to info rather than failing start-up.
func TestInitLoggerAcceptsAnUnknownLevel(t *testing.T) {
	if err := InitLogger("not-a-level"); err != nil {
		t.Errorf("an unknown level should fall back to info, got: %v", err)
	}
	if Log == nil {
		t.Error("Log is nil after InitLogger with an unknown level")
	}
}
