package telemetry

import (
	"context"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ServiceName != "kayan" {
		t.Fatalf("unexpected service name: %q", cfg.ServiceName)
	}
	if !cfg.Enabled {
		t.Fatal("expected telemetry to be enabled by default")
	}
	if cfg.SamplingRate != 1.0 {
		t.Fatalf("unexpected sampling rate: %v", cfg.SamplingRate)
	}
	if cfg.InsecureOTLP {
		t.Fatal("expected insecure OTLP to be disabled by default")
	}
}

func TestNewProviderDisabledIsSafe(t *testing.T) {
	provider, err := NewProvider(Config{ServiceName: "test", Enabled: false})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	provider.RecordLogin(context.Background(), "password", true, "tenant-1")
	provider.RecordRegistration(context.Background(), "password", false, "tenant-1")
	provider.RecordMFA(context.Background(), "totp", true)
	provider.RecordRateLimit(context.Background(), "login", "ip:1")
	provider.RecordLockout(context.Background(), "lock")
	provider.RecordAuthDuration(context.Background(), "password", time.Second)
	provider.SessionCreated(context.Background(), "tenant-1")
	provider.SessionDestroyed(context.Background(), "tenant-1")

	if provider.Tracer() == nil {
		t.Fatal("expected fallback tracer")
	}
	if provider.Meter() == nil {
		t.Fatal("expected fallback meter")
	}
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}

func TestNewProviderEnabledInitializesTelemetry(t *testing.T) {
	previousTracerProvider := otel.GetTracerProvider()
	previousMeterProvider := otel.GetMeterProvider()
	t.Cleanup(func() {
		otel.SetTracerProvider(previousTracerProvider)
		otel.SetMeterProvider(previousMeterProvider)
	})

	provider, err := NewProvider(Config{
		ServiceName:    "kayan-test",
		ServiceVersion: "1.2.3",
		Environment:    "test",
		Enabled:        true,
		SamplingRate:   0.5,
	})
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	if provider.tracerProvider == nil {
		t.Fatal("expected tracer provider to be initialized")
	}
	if provider.meterProvider == nil {
		t.Fatal("expected meter provider to be initialized")
	}
	if provider.Tracer() == nil || provider.Tracer() == trace.NewNoopTracerProvider().Tracer("noop") {
		t.Fatal("expected non-nil tracer")
	}

	provider.RecordLogin(context.Background(), "password", true, "tenant-1")
	provider.RecordRegistration(context.Background(), "password", true, "tenant-1")
	provider.RecordMFA(context.Background(), "totp", false)
	provider.RecordRateLimit(context.Background(), "login", "ip:1")
	provider.RecordLockout(context.Background(), "lock")
	provider.RecordAuthDuration(context.Background(), "password", 1500*time.Millisecond)
	provider.SessionCreated(context.Background(), "tenant-1")
	provider.SessionDestroyed(context.Background(), "tenant-1")

	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
}
