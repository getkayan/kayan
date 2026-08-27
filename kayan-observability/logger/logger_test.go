package logger

import (
	"testing"
)

func TestInitLogger_ValidLevels(t *testing.T) {
	levels := []string{"debug", "info", "warn", "error"}
	for _, level := range levels {
		t.Run(level, func(t *testing.T) {
			InitLogger(level)
			if Log == nil {
				t.Fatal("expected Log to be initialized")
			}
		})
	}
}

func TestInitLogger_InvalidLevel(t *testing.T) {
	InitLogger("invalid_level")
	if Log == nil {
		t.Fatal("expected Log to fall back to info level on invalid input")
	}
}

func TestInitLogger_EmptyLevel(t *testing.T) {
	InitLogger("")
	if Log == nil {
		t.Fatal("expected Log to fall back on empty level")
	}
}
