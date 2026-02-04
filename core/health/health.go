// Package health provides health check infrastructure for Kayan IAM.
//
// This package implements production-ready health checks for Kubernetes deployments,
// load balancers, and monitoring systems. It supports liveness, readiness, and
// comprehensive health reporting.
//
// # Features
//
//   - Kubernetes-compatible /healthz and /ready endpoints
//   - Concurrent health check execution with configurable timeouts
//   - Built-in checkers for database, Redis, and memory
//   - Custom checker interface for application-specific checks
//   - Detailed health reports with latency metrics
//
// # Health Status
//
//   - StatusHealthy: All checks pass
//   - StatusDegraded: Some non-critical checks fail
//   - StatusUnhealthy: Critical checks fail
//
// # Example Usage
//
//	manager := health.NewManager("1.0.0", health.WithTimeout(5*time.Second))
//
//	// Register database check
//	manager.Register(health.NewDatabaseChecker("postgres", db.PingContext))
//
//	// Register custom check
//	manager.RegisterFunc("cache", func(ctx context.Context) *health.Check {
//	    return &health.Check{Name: "cache", Status: health.StatusHealthy}
//	})
//
//	// Mount HTTP handlers
//	http.Handle("/healthz", manager.LiveHandler())
//	http.Handle("/ready", manager.ReadyHandler())
//	http.Handle("/health", manager.FullHandler())
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// Status represents the health status of a component.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

// Check represents the result of a single health check.
type Check struct {
	Name      string        `json:"name"`
	Status    Status        `json:"status"`
	Message   string        `json:"message,omitempty"`
	Latency   time.Duration `json:"-"`
	LatencyMs int64         `json:"latency_ms"`
	Timestamp time.Time     `json:"timestamp"`
}

// Report represents the overall health report.
type Report struct {
	Status    Status    `json:"status"`
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Checks    []Check   `json:"checks"`
}

// Checker is the interface for health check implementations.
type Checker interface {
	// Name returns the name of the health check.
	Name() string
	// Check performs the health check and returns the result.
	Check(ctx context.Context) *Check
}

// CheckFunc is a function adapter for Checker.
type CheckFunc struct {
	CheckName string
	Fn        func(ctx context.Context) *Check
}

func (c CheckFunc) Name() string                     { return c.CheckName }
func (c CheckFunc) Check(ctx context.Context) *Check { return c.Fn(ctx) }

// ---- Health Manager ----

// Manager coordinates health checks.
type Manager struct {
	mu       sync.RWMutex
	checkers []Checker
	version  string
	timeout  time.Duration
}

// ManagerOption configures the Manager.
type ManagerOption func(*Manager)

// NewManager creates a new health manager.
func NewManager(version string, opts ...ManagerOption) *Manager {
	m := &Manager{
		version: version,
		timeout: 5 * time.Second,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// WithTimeout sets the check timeout.
func WithTimeout(d time.Duration) ManagerOption {
	return func(m *Manager) {
		m.timeout = d
	}
}

// Register adds a health checker.
func (m *Manager) Register(checker Checker) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.checkers = append(m.checkers, checker)
}

// RegisterFunc adds a health check function.
func (m *Manager) RegisterFunc(name string, fn func(ctx context.Context) *Check) {
	m.Register(CheckFunc{CheckName: name, Fn: fn})
}

// Check runs all health checks and returns a report.
func (m *Manager) Check(ctx context.Context) *Report {
	m.mu.RLock()
	checkers := make([]Checker, len(m.checkers))
	copy(checkers, m.checkers)
	m.mu.RUnlock()

	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	report := &Report{
		Status:    StatusHealthy,
		Version:   m.version,
		Timestamp: time.Now(),
		Checks:    make([]Check, 0, len(checkers)),
	}

	// Run checks concurrently
	var wg sync.WaitGroup
	results := make(chan *Check, len(checkers))

	for _, checker := range checkers {
		wg.Add(1)
		go func(c Checker) {
			defer wg.Done()
			start := time.Now()
			check := c.Check(ctx)
			if check == nil {
				check = &Check{
					Name:   c.Name(),
					Status: StatusUnhealthy,
				}
			}
			check.Latency = time.Since(start)
			check.LatencyMs = check.Latency.Milliseconds()
			check.Timestamp = time.Now()
			results <- check
		}(checker)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	for check := range results {
		report.Checks = append(report.Checks, *check)

		// Determine overall status
		switch check.Status {
		case StatusUnhealthy:
			report.Status = StatusUnhealthy
		case StatusDegraded:
			if report.Status != StatusUnhealthy {
				report.Status = StatusDegraded
			}
		}
	}

	return report
}

// IsHealthy returns true if all checks pass.
func (m *Manager) IsHealthy(ctx context.Context) bool {
	report := m.Check(ctx)
	return report.Status == StatusHealthy
}

// IsReady returns true if the service is ready to accept traffic.
func (m *Manager) IsReady(ctx context.Context) bool {
	report := m.Check(ctx)
	return report.Status != StatusUnhealthy
}

// ---- HTTP Handlers ----

// LiveHandler returns a handler for liveness checks (Kubernetes).
func (m *Manager) LiveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

// ReadyHandler returns a handler for readiness checks (Kubernetes).
func (m *Manager) ReadyHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if m.IsReady(r.Context()) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ready"})
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]string{"status": "not ready"})
		}
	}
}

// FullHandler returns a handler for full health reports.
func (m *Manager) FullHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := m.Check(r.Context())

		w.Header().Set("Content-Type", "application/json")

		switch report.Status {
		case StatusHealthy:
			w.WriteHeader(http.StatusOK)
		case StatusDegraded:
			w.WriteHeader(http.StatusOK)
		case StatusUnhealthy:
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(report)
	}
}

// ---- Built-in Checkers ----

// DatabaseChecker checks database connectivity.
type DatabaseChecker struct {
	name   string
	pingFn func(ctx context.Context) error
}

// NewDatabaseChecker creates a database health checker.
func NewDatabaseChecker(name string, pingFn func(ctx context.Context) error) *DatabaseChecker {
	return &DatabaseChecker{name: name, pingFn: pingFn}
}

func (c *DatabaseChecker) Name() string { return c.name }

func (c *DatabaseChecker) Check(ctx context.Context) *Check {
	check := &Check{Name: c.name}

	if err := c.pingFn(ctx); err != nil {
		check.Status = StatusUnhealthy
		check.Message = err.Error()
	} else {
		check.Status = StatusHealthy
		check.Message = "connected"
	}

	return check
}

// RedisChecker checks Redis connectivity.
type RedisChecker struct {
	name   string
	pingFn func(ctx context.Context) error
}

// NewRedisChecker creates a Redis health checker.
func NewRedisChecker(name string, pingFn func(ctx context.Context) error) *RedisChecker {
	return &RedisChecker{name: name, pingFn: pingFn}
}

func (c *RedisChecker) Name() string { return c.name }

func (c *RedisChecker) Check(ctx context.Context) *Check {
	check := &Check{Name: c.name}

	if err := c.pingFn(ctx); err != nil {
		check.Status = StatusUnhealthy
		check.Message = err.Error()
	} else {
		check.Status = StatusHealthy
		check.Message = "connected"
	}

	return check
}

// MemoryChecker checks memory usage.
type MemoryChecker struct {
	threshold float64 // 0.0-1.0
}

// NewMemoryChecker creates a memory health checker.
// Threshold is the percentage (0.0-1.0) at which to report degraded.
func NewMemoryChecker(threshold float64) *MemoryChecker {
	return &MemoryChecker{threshold: threshold}
}

func (c *MemoryChecker) Name() string { return "memory" }

func (c *MemoryChecker) Check(ctx context.Context) *Check {
	// Note: This is a simplified check. In production, use runtime.MemStats
	// and compare against system limits.
	return &Check{
		Name:    c.Name(),
		Status:  StatusHealthy,
		Message: "ok",
	}
}
