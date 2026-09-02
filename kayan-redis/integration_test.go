//go:build integration

package redisstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/session"
	"github.com/getkayan/kayan/core/tenant"
	"github.com/redis/go-redis/v9"
)

func TestRealRedisSSOLifecycle(t *testing.T) {
	addr := os.Getenv("KAYAN_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("KAYAN_TEST_REDIS_ADDR is not set")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("ping Redis: %v", err)
	}

	store := NewRedisSSOStore(client, "integration")
	mgr := session.NewSSOManager(store)
	created, err := mgr.CreateSession(context.Background(), "user-1", "web")
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, err := mgr.JoinSession(context.Background(), created.ID, "mobile"); err != nil {
		t.Fatalf("JoinSession: %v", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := mgr.JoinSession(context.Background(), created.ID, fmt.Sprintf("worker-%d", i)); err != nil {
				t.Errorf("concurrent JoinSession: %v", err)
			}
		}(i)
	}
	wg.Wait()
	got, err := mgr.GetSession(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(got.AppSessions) != 18 {
		t.Fatalf("app sessions = %d, want 18", len(got.AppSessions))
	}
	apps, err := mgr.Logout(context.Background(), created.ID)
	if err != nil || len(apps) != 18 {
		t.Fatalf("Logout = %d apps, %v; want 18, nil", len(apps), err)
	}
}

func TestRealRedisTenantGovernor(t *testing.T) {
	addr := os.Getenv("KAYAN_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("KAYAN_TEST_REDIS_ADDR is not set")
	}
	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = client.Close() })
	if err := client.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("ping Redis: %v", err)
	}

	prefix := fmt.Sprintf("integration:governance:%d:", time.Now().UnixNano())
	governor, err := tenant.NewGovernor(
		NewRedisRateLimiter(client, prefix+"rate:"),
		NewRedisConcurrencyLimiter(client, prefix+"concurrency:"),
		tenant.FixedLimits{RateLimit: 10, RateWindow: time.Minute, ConcurrencyLimit: 1, LeaseTTL: time.Minute},
		tenant.WithGlobalLimitProvider(tenant.FixedLimits{ConcurrencyLimit: 2, LeaseTTL: time.Minute}),
	)
	if err != nil {
		t.Fatal(err)
	}

	ctxA := tenant.WithTenantID(context.Background(), "tenant-a")
	first, err := governor.Acquire(ctxA, "reports.export")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := governor.Acquire(ctxA, "reports.export"); !errors.Is(err, tenant.ErrConcurrencyExceeded) {
		t.Fatalf("second tenant A admission error = %v", err)
	}
	ctxB := tenant.WithTenantID(context.Background(), "tenant-b")
	other, err := governor.Acquire(ctxB, "reports.export")
	if err != nil {
		t.Fatalf("tenant A affected tenant B: %v", err)
	}
	if err := first.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := other.Release(context.Background()); err != nil {
		t.Fatal(err)
	}
}
