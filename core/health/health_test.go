package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestManager_NoCheckers(t *testing.T) {
	mgr := NewManager("1.0.0")
	report := mgr.Check(context.Background())
	if report.Status != StatusHealthy {
		t.Errorf("expected healthy with no checkers, got %s", report.Status)
	}
	if report.Version != "1.0.0" {
		t.Errorf("expected version 1.0.0, got %s", report.Version)
	}
	if len(report.Checks) != 0 {
		t.Errorf("expected 0 checks, got %d", len(report.Checks))
	}
}

func TestManager_HealthyChecker(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("test", func(_ context.Context) *Check {
		return &Check{Name: "test", Status: StatusHealthy, Message: "ok"}
	})

	report := mgr.Check(context.Background())
	if report.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", report.Status)
	}
	if len(report.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(report.Checks))
	}
	if report.Checks[0].Name != "test" {
		t.Errorf("expected check name 'test', got %s", report.Checks[0].Name)
	}
}

func TestManager_UnhealthyChecker(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("db", func(_ context.Context) *Check {
		return &Check{Name: "db", Status: StatusUnhealthy, Message: "connection refused"}
	})

	report := mgr.Check(context.Background())
	if report.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy, got %s", report.Status)
	}
}

func TestManager_DegradedChecker(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("cache", func(_ context.Context) *Check {
		return &Check{Name: "cache", Status: StatusDegraded, Message: "slow"}
	})

	report := mgr.Check(context.Background())
	if report.Status != StatusDegraded {
		t.Errorf("expected degraded, got %s", report.Status)
	}
}

func TestManager_MixedStatus(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("db", func(_ context.Context) *Check {
		return &Check{Name: "db", Status: StatusHealthy}
	})
	mgr.RegisterFunc("cache", func(_ context.Context) *Check {
		return &Check{Name: "cache", Status: StatusDegraded}
	})

	report := mgr.Check(context.Background())
	if report.Status != StatusDegraded {
		t.Errorf("expected degraded when one check is degraded, got %s", report.Status)
	}
}

func TestManager_UnhealthyOverridesDegraded(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("db", func(_ context.Context) *Check {
		return &Check{Name: "db", Status: StatusUnhealthy}
	})
	mgr.RegisterFunc("cache", func(_ context.Context) *Check {
		return &Check{Name: "cache", Status: StatusDegraded}
	})

	report := mgr.Check(context.Background())
	if report.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy to override degraded, got %s", report.Status)
	}
}

func TestManager_IsHealthy(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("ok", func(_ context.Context) *Check {
		return &Check{Name: "ok", Status: StatusHealthy}
	})

	if !mgr.IsHealthy(context.Background()) {
		t.Error("expected IsHealthy to return true")
	}
}

func TestManager_IsReady(t *testing.T) {
	mgr := NewManager("1.0.0")

	// Degraded is still ready
	mgr.RegisterFunc("cache", func(_ context.Context) *Check {
		return &Check{Name: "cache", Status: StatusDegraded}
	})
	if !mgr.IsReady(context.Background()) {
		t.Error("expected degraded to still be ready")
	}
}

func TestManager_IsNotReady(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("db", func(_ context.Context) *Check {
		return &Check{Name: "db", Status: StatusUnhealthy}
	})

	if mgr.IsReady(context.Background()) {
		t.Error("expected unhealthy to not be ready")
	}
}

func TestManager_LatencyTracking(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("slow", func(_ context.Context) *Check {
		time.Sleep(10 * time.Millisecond)
		return &Check{Name: "slow", Status: StatusHealthy}
	})

	report := mgr.Check(context.Background())
	if len(report.Checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(report.Checks))
	}
	if report.Checks[0].Latency < 10*time.Millisecond {
		t.Errorf("expected latency >= 10ms, got %v", report.Checks[0].Latency)
	}
	if report.Checks[0].LatencyMs < 10 {
		t.Errorf("expected LatencyMs >= 10, got %d", report.Checks[0].LatencyMs)
	}
}

func TestManager_NilCheckResult(t *testing.T) {
	mgr := NewManager("1.0.0")
	mgr.RegisterFunc("nil", func(_ context.Context) *Check {
		return nil
	})

	report := mgr.Check(context.Background())
	if report.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy for nil check result, got %s", report.Status)
	}
}

func TestManager_ConcurrentRegistration(t *testing.T) {
	mgr := NewManager("1.0.0")

	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			mgr.RegisterFunc("check", func(_ context.Context) *Check {
				return &Check{Name: "check", Status: StatusHealthy}
			})
		}
		close(done)
	}()

	// Concurrent checks while registering
	for i := 0; i < 50; i++ {
		mgr.Check(context.Background())
	}
	<-done
}

func TestManager_WithTimeout(t *testing.T) {
	mgr := NewManager("1.0.0", WithTimeout(100*time.Millisecond))
	mgr.RegisterFunc("fast", func(_ context.Context) *Check {
		return &Check{Name: "fast", Status: StatusHealthy}
	})

	report := mgr.Check(context.Background())
	if report.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", report.Status)
	}
}

func TestDatabaseChecker_Healthy(t *testing.T) {
	checker := NewDatabaseChecker("postgres", func(_ context.Context) error {
		return nil
	})
	if checker.Name() != "postgres" {
		t.Errorf("expected name postgres, got %s", checker.Name())
	}

	check := checker.Check(context.Background())
	if check.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", check.Status)
	}
}

func TestDatabaseChecker_Unhealthy(t *testing.T) {
	checker := NewDatabaseChecker("postgres", func(_ context.Context) error {
		return errors.New("connection refused")
	})

	check := checker.Check(context.Background())
	if check.Status != StatusUnhealthy {
		t.Errorf("expected unhealthy, got %s", check.Status)
	}
	if check.Message != "connection refused" {
		t.Errorf("expected error message, got %s", check.Message)
	}
}

func TestRedisChecker_Healthy(t *testing.T) {
	checker := NewRedisChecker("redis", func(_ context.Context) error {
		return nil
	})
	if checker.Name() != "redis" {
		t.Errorf("expected name redis, got %s", checker.Name())
	}

	check := checker.Check(context.Background())
	if check.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", check.Status)
	}
}

func TestMemoryChecker(t *testing.T) {
	checker := NewMemoryChecker(0.9)
	if checker.Name() != "memory" {
		t.Errorf("expected name memory, got %s", checker.Name())
	}

	check := checker.Check(context.Background())
	if check.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", check.Status)
	}
}

func TestCheckFunc_Adapter(t *testing.T) {
	cf := CheckFunc{
		CheckName: "custom",
		Fn: func(_ context.Context) *Check {
			return &Check{Name: "custom", Status: StatusHealthy}
		},
	}
	if cf.Name() != "custom" {
		t.Errorf("expected name custom, got %s", cf.Name())
	}
	check := cf.Check(context.Background())
	if check.Status != StatusHealthy {
		t.Errorf("expected healthy, got %s", check.Status)
	}
}
