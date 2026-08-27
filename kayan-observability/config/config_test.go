package config

import (
	"os"
	"testing"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear any env vars that might interfere
	os.Unsetenv("DB_TYPE")
	os.Unsetenv("DSN")
	os.Unsetenv("LOG_LEVEL")
	os.Unsetenv("SKIP_AUTO_MIGRATE")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.DBType != "sqlite" {
		t.Errorf("expected default DBType 'sqlite', got %q", cfg.DBType)
	}
	if cfg.DSN != "kayan.db" {
		t.Errorf("expected default DSN 'kayan.db', got %q", cfg.DSN)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("expected default LogLevel 'info', got %q", cfg.LogLevel)
	}
	if cfg.SkipAutoMigrate {
		t.Error("expected default SkipAutoMigrate to be false")
	}
}

func TestLoadConfig_EnvOverride(t *testing.T) {
	t.Setenv("DB_TYPE", "postgres")
	t.Setenv("DSN", "postgres://localhost:5432/kayan")
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("SKIP_AUTO_MIGRATE", "true")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.DBType != "postgres" {
		t.Errorf("expected DBType 'postgres', got %q", cfg.DBType)
	}
	if cfg.DSN != "postgres://localhost:5432/kayan" {
		t.Errorf("expected DSN override, got %q", cfg.DSN)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("expected LogLevel 'debug', got %q", cfg.LogLevel)
	}
}
