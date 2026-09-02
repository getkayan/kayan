package redisstore

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/getkayan/kayan/core/tenant"
	"github.com/redis/go-redis/v9"
)

func setupConcurrencyLimiter(t *testing.T) (*RedisConcurrencyLimiter, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return NewRedisConcurrencyLimiter(client, "test:concurrency:"), server
}

func TestRedisConcurrencyCapacityReleaseAndSeparateKeys(t *testing.T) {
	limiter, _ := setupConcurrencyLimiter(t)
	ctx := context.Background()
	first, allowed, _, err := limiter.Acquire(ctx, "tenant-a", 1, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("first acquire = %v, %v", allowed, err)
	}
	if _, allowed, retry, err := limiter.Acquire(ctx, "tenant-a", 1, time.Minute); err != nil || allowed || retry <= 0 {
		t.Fatalf("second acquire = allowed %v, retry %v, err %v", allowed, retry, err)
	}
	other, allowed, _, err := limiter.Acquire(ctx, "tenant-b", 1, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("one key consumed another key's capacity: %v, %v", allowed, err)
	}
	if err := limiter.Release(ctx, first); err != nil {
		t.Fatal(err)
	}
	again, allowed, _, err := limiter.Acquire(ctx, "tenant-a", 1, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("released capacity was not returned: %v, %v", allowed, err)
	}
	_ = limiter.Release(ctx, again)
	_ = limiter.Release(ctx, other)
}

func TestRedisConcurrencyExpiryRenewalAndStaleRelease(t *testing.T) {
	limiter, server := setupConcurrencyLimiter(t)
	now := time.Unix(1_700_000_000, 0)
	server.SetTime(now)
	ctx := context.Background()

	old, allowed, _, err := limiter.Acquire(ctx, "jobs", 1, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("acquire = %v, %v", allowed, err)
	}
	now = now.Add(30 * time.Second)
	server.SetTime(now)
	renewed, ok, err := limiter.Renew(ctx, old, time.Minute)
	if err != nil || !ok || !renewed.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("renew = %#v, %v, %v", renewed, ok, err)
	}

	// Redis also expires abandoned keys even when no later request prunes them.
	now = now.Add(61 * time.Second)
	server.SetTime(now)
	server.FastForward(61 * time.Second)
	current, allowed, _, err := limiter.Acquire(ctx, "jobs", 1, time.Minute)
	if err != nil || !allowed {
		t.Fatalf("acquire after expiry = %v, %v", allowed, err)
	}
	if err := limiter.Release(ctx, old); err != nil {
		t.Fatal(err)
	}
	if _, allowed, _, err := limiter.Acquire(ctx, "jobs", 1, time.Minute); err != nil || allowed {
		t.Fatalf("stale owner released current lease: allowed=%v err=%v", allowed, err)
	}
	_ = limiter.Release(ctx, current)
}

func TestRedisConcurrencyRenewRejectsLostLease(t *testing.T) {
	limiter, server := setupConcurrencyLimiter(t)
	ctx := context.Background()
	lease, allowed, _, err := limiter.Acquire(ctx, "work", 1, time.Second)
	if err != nil || !allowed {
		t.Fatalf("acquire = %v, %v", allowed, err)
	}
	server.FastForward(2 * time.Second)
	if _, ok, err := limiter.Renew(ctx, lease, time.Minute); err != nil || ok {
		t.Fatalf("renew lost lease = %v, %v; want false, nil", ok, err)
	}
}

func TestRedisConcurrencyAtomicUnderContention(t *testing.T) {
	limiter, _ := setupConcurrencyLimiter(t)
	ctx := context.Background()
	const workers = 96
	const limit = 5
	start := make(chan struct{})
	leases := make(chan tenant.ConcurrencyLease, workers)
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

	var acquired []tenant.ConcurrencyLease
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

func TestRedisConcurrencyValidatesInputsAndContext(t *testing.T) {
	limiter, _ := setupConcurrencyLimiter(t)
	if _, _, _, err := limiter.Acquire(context.Background(), "work", 0, time.Minute); err != tenant.ErrInvalidLimits {
		t.Fatalf("invalid limits error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, _, err := limiter.Acquire(ctx, "work", 1, time.Minute); err != context.Canceled {
		t.Fatalf("cancelled acquire error = %v", err)
	}
}
