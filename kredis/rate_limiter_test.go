package kredis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTestRateLimiter(t *testing.T) (*RedisRateLimiter, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rl := NewRedisRateLimiter(client, "")
	return rl, mr
}

func TestRedisRateLimiter_AllowUnderLimit(t *testing.T) {
	rl, mr := setupTestRateLimiter(t)
	defer mr.Close()
	ctx := context.Background()

	allowed, remaining, err := rl.Allow(ctx, "login:user1", 5, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !allowed {
		t.Fatal("expected request to be allowed")
	}
	if remaining != 4 {
		t.Fatalf("expected 4 remaining, got %d", remaining)
	}
}

func TestRedisRateLimiter_DenyOverLimit(t *testing.T) {
	rl, mr := setupTestRateLimiter(t)
	defer mr.Close()
	ctx := context.Background()

	limit := 3
	window := time.Minute

	// Exhaust the limit
	for i := 0; i < limit; i++ {
		allowed, _, err := rl.Allow(ctx, "login:user1", limit, window)
		if err != nil {
			t.Fatalf("Allow #%d: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("expected request #%d to be allowed", i+1)
		}
	}

	// Next request should be denied
	allowed, _, err := rl.Allow(ctx, "login:user1", limit, window)
	if err != nil {
		t.Fatalf("Allow over limit: %v", err)
	}
	if allowed {
		t.Fatal("expected request to be denied over limit")
	}
}

func TestRedisRateLimiter_Reset(t *testing.T) {
	rl, mr := setupTestRateLimiter(t)
	defer mr.Close()
	ctx := context.Background()

	limit := 2
	window := time.Minute

	// Use up the limit
	rl.Allow(ctx, "login:user1", limit, window)
	rl.Allow(ctx, "login:user1", limit, window)

	// Reset
	if err := rl.Reset(ctx, "login:user1"); err != nil {
		t.Fatalf("Reset: %v", err)
	}

	// Should be allowed again
	allowed, remaining, err := rl.Allow(ctx, "login:user1", limit, window)
	if err != nil {
		t.Fatalf("Allow after reset: %v", err)
	}
	if !allowed {
		t.Fatal("expected request to be allowed after reset")
	}
	if remaining != 1 {
		t.Fatalf("expected 1 remaining after reset, got %d", remaining)
	}
}

func TestRedisRateLimiter_SeparateKeys(t *testing.T) {
	rl, mr := setupTestRateLimiter(t)
	defer mr.Close()
	ctx := context.Background()

	// Use up limit for user1
	rl.Allow(ctx, "login:user1", 1, time.Minute)

	// user2 should still be allowed
	allowed, _, err := rl.Allow(ctx, "login:user2", 1, time.Minute)
	if err != nil {
		t.Fatalf("Allow user2: %v", err)
	}
	if !allowed {
		t.Fatal("expected user2 request to be allowed (separate key)")
	}
}

func TestRedisRateLimiter_WindowExpiry(t *testing.T) {
	rl, mr := setupTestRateLimiter(t)
	defer mr.Close()
	ctx := context.Background()

	limit := 1
	window := 5 * time.Minute

	// Use up the limit
	rl.Allow(ctx, "login:user1", limit, window)

	// Fast-forward past the window
	mr.FastForward(6 * time.Minute)

	// Should be allowed again
	allowed, _, err := rl.Allow(ctx, "login:user1", limit, window)
	if err != nil {
		t.Fatalf("Allow after window: %v", err)
	}
	if !allowed {
		t.Fatal("expected request to be allowed after window expiry")
	}
}

func TestRedisRateLimiter_RemainingCountDecreases(t *testing.T) {
	rl, mr := setupTestRateLimiter(t)
	defer mr.Close()
	ctx := context.Background()

	limit := 5
	window := time.Minute

	for i := 0; i < limit; i++ {
		allowed, remaining, err := rl.Allow(ctx, "login:user1", limit, window)
		if err != nil {
			t.Fatalf("Allow #%d: %v", i+1, err)
		}
		if !allowed {
			t.Fatalf("expected request #%d to be allowed", i+1)
		}
		expectedRemaining := limit - i - 1
		if remaining != expectedRemaining {
			t.Fatalf("request #%d: expected %d remaining, got %d", i+1, expectedRemaining, remaining)
		}
	}
}

func TestRedisRateLimiter_CustomPrefix(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rl := NewRedisRateLimiter(client, "myapp:rl:")
	ctx := context.Background()

	rl.Allow(ctx, "api:endpoint1", 10, time.Minute)

	keys, err := client.Keys(ctx, "myapp:rl:*").Result()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("expected keys with custom prefix")
	}
}
