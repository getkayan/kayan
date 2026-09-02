package tenant

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func governedContext(id string) context.Context {
	return WithTenantID(context.Background(), id)
}

func testLimits(rate, concurrency int) FixedLimits {
	return FixedLimits{
		RateLimit: rate, RateWindow: time.Minute,
		ConcurrencyLimit: concurrency, LeaseTTL: time.Minute,
	}
}

func newMemoryGovernor(t *testing.T, limits FixedLimits, opts ...GovernorOption) *Governor {
	t.Helper()
	governor, err := NewGovernor(
		NewMemoryGovernanceRateLimiter(), NewMemoryConcurrencyLimiter(), limits, opts...,
	)
	if err != nil {
		t.Fatal(err)
	}
	return governor
}

func TestGovernorRateBudgetsAreIndependentPerTenant(t *testing.T) {
	governor := newMemoryGovernor(t, testLimits(1, 0))

	permit, err := governor.Acquire(governedContext("tenant-a"), "tickets.read")
	if err != nil {
		t.Fatalf("tenant A first admission: %v", err)
	}
	if err := permit.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := governor.Acquire(governedContext("tenant-a"), "tickets.read"); !errors.Is(err, ErrRateLimitExceeded) {
		t.Fatalf("tenant A second admission error = %v, want ErrRateLimitExceeded", err)
	}

	permit, err = governor.Acquire(governedContext("tenant-b"), "tickets.read")
	if err != nil {
		t.Fatalf("tenant A consumed tenant B's budget: %v", err)
	}
	_ = permit.Release(context.Background())
}

func TestGovernorConcurrencyBudgetsAreIndependentPerTenant(t *testing.T) {
	governor := newMemoryGovernor(t, testLimits(0, 1))
	ctxA := governedContext("tenant-a")

	first, err := governor.Acquire(ctxA, "reports.export")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := governor.Acquire(ctxA, "reports.export"); !errors.Is(err, ErrConcurrencyExceeded) {
		t.Fatalf("second tenant A admission error = %v, want ErrConcurrencyExceeded", err)
	}

	other, err := governor.Acquire(governedContext("tenant-b"), "reports.export")
	if err != nil {
		t.Fatalf("tenant A occupied tenant B's capacity: %v", err)
	}
	if err := other.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}

	again, err := governor.Acquire(ctxA, "reports.export")
	if err != nil {
		t.Fatalf("released capacity was not returned: %v", err)
	}
	_ = again.Release(context.Background())
}

func TestGovernorGlobalCapacityProtectsTheDeployment(t *testing.T) {
	governor := newMemoryGovernor(t, testLimits(0, 2), WithGlobalLimitProvider(testLimits(0, 1)))

	first, err := governor.Acquire(governedContext("tenant-a"), "password.hash")
	if err != nil {
		t.Fatal(err)
	}
	_, err = governor.Acquire(governedContext("tenant-b"), "password.hash")
	var limitErr *LimitError
	if !errors.As(err, &limitErr) || limitErr.Scope != GovernanceScopeGlobal {
		t.Fatalf("second admission error = %#v, want global LimitError", err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The denied attempt acquired tenant B's lease before checking global
	// capacity. It must have rolled that lease back.
	second, err := governor.Acquire(governedContext("tenant-b"), "password.hash")
	if err != nil {
		t.Fatalf("partial tenant lease was not rolled back: %v", err)
	}
	_ = second.Release(context.Background())
}

func TestGovernorRollbackSurvivesRequestCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(governedContext("tenant-a"))
	calls := 0
	rate := rateLimiterFunc(func(context.Context, string, int, time.Duration) (bool, int, error) {
		calls++
		if calls == 1 {
			cancel()
			return false, 0, context.Canceled
		}
		return true, 0, nil
	})
	concurrency := NewMemoryConcurrencyLimiter()
	governor, err := NewGovernor(rate, concurrency, testLimits(0, 1),
		WithGlobalLimitProvider(testLimits(1, 0)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := governor.Acquire(ctx, "reports.export"); !errors.Is(err, ErrGovernanceUnavailable) {
		t.Fatalf("cancelled global admission error = %v", err)
	}

	// The tenant lease was acquired before global admission cancelled the
	// request. Rollback must use an independent context or this retry remains
	// blocked until the lease TTL.
	permit, err := governor.Acquire(governedContext("tenant-a"), "reports.export")
	if err != nil {
		t.Fatalf("cancelled request leaked tenant capacity: %v", err)
	}
	_ = permit.Release(context.Background())
}

func TestGovernorFailsClosed(t *testing.T) {
	t.Run("missing tenant", func(t *testing.T) {
		governor := newMemoryGovernor(t, testLimits(1, 1))
		if _, err := governor.Acquire(context.Background(), "login"); !errors.Is(err, ErrNoTenant) {
			t.Fatalf("error = %v, want ErrNoTenant", err)
		}
	})

	t.Run("policy failure", func(t *testing.T) {
		providerErr := errors.New("plan database unavailable")
		governor, err := NewGovernor(nil, nil, LimitProviderFunc(func(context.Context, string, string) (ResourceLimits, error) {
			return ResourceLimits{}, providerErr
		}))
		if err != nil {
			t.Fatal(err)
		}
		_, err = governor.Acquire(governedContext("tenant-a"), "login")
		if !errors.Is(err, ErrGovernanceUnavailable) || !errors.Is(err, providerErr) {
			t.Fatalf("error = %v, want governance and provider errors", err)
		}
	})

	t.Run("missing required backend", func(t *testing.T) {
		governor, err := NewGovernor(nil, nil, testLimits(1, 0))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := governor.Acquire(governedContext("tenant-a"), "login"); !errors.Is(err, ErrGovernanceUnavailable) {
			t.Fatalf("error = %v, want ErrGovernanceUnavailable", err)
		}
	})

	t.Run("invalid operation", func(t *testing.T) {
		governor := newMemoryGovernor(t, testLimits(1, 1))
		if _, err := governor.Acquire(governedContext("tenant-a"), "ticket/123"); !errors.Is(err, ErrInvalidOperation) {
			t.Fatalf("error = %v, want ErrInvalidOperation", err)
		}
	})
}

func TestGovernorKeysDoNotExposeTenantIdentifiers(t *testing.T) {
	var seen string
	rate := rateLimiterFunc(func(_ context.Context, key string, _ int, _ time.Duration) (bool, int, error) {
		seen = key
		return true, 0, nil
	})
	governor, err := NewGovernor(rate, nil, testLimits(1, 0))
	if err != nil {
		t.Fatal(err)
	}
	permit, err := governor.Acquire(governedContext("customer-secret-name"), "tickets.read")
	if err != nil {
		t.Fatal(err)
	}
	_ = permit.Release(context.Background())
	if strings.Contains(seen, "customer-secret-name") {
		t.Fatalf("internal key exposes tenant identifier: %q", seen)
	}
}

func TestMemoryConcurrencyLeaseExpiryRenewalAndOwnership(t *testing.T) {
	limiter := NewMemoryConcurrencyLimiter()
	now := time.Unix(1_700_000_000, 0)
	limiter.now = func() time.Time { return now }
	ctx := context.Background()

	old, allowed, _, err := limiter.Acquire(ctx, "work", 1, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("first acquire = %v, %v", allowed, err)
	}
	now = now.Add(30 * time.Second)
	renewed, ok, err := limiter.Renew(ctx, old, time.Minute)
	if err != nil || !ok || !renewed.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("renew = %#v, %v, %v", renewed, ok, err)
	}

	now = now.Add(61 * time.Second)
	current, allowed, _, err := limiter.Acquire(ctx, "work", 1, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("acquire after expiry = %v, %v", allowed, err)
	}
	if err := limiter.Release(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, allowed, _, err := limiter.Acquire(ctx, "work", 1, time.Minute); err != nil || allowed {
		t.Fatalf("stale release removed current owner's lease: allowed=%v err=%v", allowed, err)
	}
	if err := limiter.Release(ctx, current); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryConcurrencyLimiterNeverExceedsCapacity(t *testing.T) {
	limiter := NewMemoryConcurrencyLimiter()
	ctx := context.Background()
	const workers = 128
	const limit = 7

	start := make(chan struct{})
	leases := make(chan ConcurrencyLease, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			lease, allowed, _, err := limiter.Acquire(ctx, "shared", limit, time.Minute)
			if err != nil {
				t.Errorf("Acquire: %v", err)
				return
			}
			if allowed {
				leases <- lease
			}
		}()
	}
	close(start)
	wg.Wait()
	close(leases)

	var acquired []ConcurrencyLease
	for lease := range leases {
		acquired = append(acquired, lease)
	}
	if len(acquired) != limit {
		t.Fatalf("acquired %d leases, want exactly %d", len(acquired), limit)
	}
	for _, lease := range acquired {
		if err := limiter.Release(ctx, lease); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPermitHooksAndIdempotentRelease(t *testing.T) {
	var decisions, releases int
	governor := newMemoryGovernor(t, testLimits(0, 1), WithGovernorHooks(GovernorHooks{
		OnDecision: func(context.Context, GovernanceDecision) { decisions++ },
		OnRelease:  func(context.Context, GovernanceUsage) { releases++ },
	}))
	permit, err := governor.Acquire(governedContext("tenant-a"), "jobs.run")
	if err != nil {
		t.Fatal(err)
	}
	if err := permit.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := permit.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if decisions != 1 || releases != 1 {
		t.Fatalf("decisions=%d releases=%d, want 1 each", decisions, releases)
	}
}

type rateLimiterFunc func(context.Context, string, int, time.Duration) (bool, int, error)

func (f rateLimiterFunc) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	return f(ctx, key, limit, window)
}
