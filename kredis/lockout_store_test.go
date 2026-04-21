package kredis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func setupTestLockoutStore(t *testing.T) (*RedisLockoutStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisLockoutStore(client, "")
	return store, mr
}

func TestRedisLockoutStore_RecordFailure(t *testing.T) {
	store, mr := setupTestLockoutStore(t)
	defer mr.Close()
	ctx := context.Background()

	count, err := store.RecordFailure(ctx, "user@example.com", 10*time.Minute)
	if err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1, got %d", count)
	}

	count, err = store.RecordFailure(ctx, "user@example.com", 10*time.Minute)
	if err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected count 2, got %d", count)
	}
}

func TestRedisLockoutStore_ClearFailures(t *testing.T) {
	store, mr := setupTestLockoutStore(t)
	defer mr.Close()
	ctx := context.Background()

	store.RecordFailure(ctx, "user@example.com", 10*time.Minute)
	store.RecordFailure(ctx, "user@example.com", 10*time.Minute)

	if err := store.ClearFailures(ctx, "user@example.com"); err != nil {
		t.Fatalf("ClearFailures: %v", err)
	}

	// After clear, next failure should be count 1
	count, err := store.RecordFailure(ctx, "user@example.com", 10*time.Minute)
	if err != nil {
		t.Fatalf("RecordFailure after clear: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1 after clear, got %d", count)
	}
}

func TestRedisLockoutStore_Lock(t *testing.T) {
	store, mr := setupTestLockoutStore(t)
	defer mr.Close()
	ctx := context.Background()

	if err := store.Lock(ctx, "user@example.com", 30*time.Minute); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	locked, until, err := store.IsLocked(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("IsLocked: %v", err)
	}
	if !locked {
		t.Fatal("expected user to be locked")
	}
	if until.IsZero() {
		t.Fatal("expected non-zero lock expiry")
	}
}

func TestRedisLockoutStore_IsLocked_NotLocked(t *testing.T) {
	store, mr := setupTestLockoutStore(t)
	defer mr.Close()
	ctx := context.Background()

	locked, _, err := store.IsLocked(ctx, "nobody@example.com")
	if err != nil {
		t.Fatalf("IsLocked: %v", err)
	}
	if locked {
		t.Fatal("expected user not to be locked")
	}
}

func TestRedisLockoutStore_LockExpiry(t *testing.T) {
	store, mr := setupTestLockoutStore(t)
	defer mr.Close()
	ctx := context.Background()

	store.Lock(ctx, "user@example.com", 5*time.Minute)

	// Fast-forward past the lock duration
	mr.FastForward(6 * time.Minute)

	locked, _, err := store.IsLocked(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("IsLocked after expiry: %v", err)
	}
	if locked {
		t.Fatal("expected lock to have expired")
	}
}

func TestRedisLockoutStore_FailureTTLExpiry(t *testing.T) {
	store, mr := setupTestLockoutStore(t)
	defer mr.Close()
	ctx := context.Background()

	store.RecordFailure(ctx, "user@example.com", 5*time.Minute)
	store.RecordFailure(ctx, "user@example.com", 5*time.Minute)

	// Fast-forward past the failure TTL
	mr.FastForward(6 * time.Minute)

	// After TTL expires, next failure should restart the count
	count, err := store.RecordFailure(ctx, "user@example.com", 5*time.Minute)
	if err != nil {
		t.Fatalf("RecordFailure after TTL: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1 after TTL expiry, got %d", count)
	}
}

func TestRedisLockoutStore_CustomPrefix(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisLockoutStore(client, "custom:prefix:")
	ctx := context.Background()

	store.RecordFailure(ctx, "user1", 10*time.Minute)

	// Verify the key was stored with custom prefix
	keys, err := client.Keys(ctx, "custom:prefix:*").Result()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("expected keys with custom prefix")
	}
}

func TestRedisLockoutStore_LockClearsFailures(t *testing.T) {
	store, mr := setupTestLockoutStore(t)
	defer mr.Close()
	ctx := context.Background()

	// Record some failures
	store.RecordFailure(ctx, "user@example.com", 10*time.Minute)
	store.RecordFailure(ctx, "user@example.com", 10*time.Minute)

	// Lock should clear failures
	store.Lock(ctx, "user@example.com", 30*time.Minute)

	// After lock expires, failures should have been cleared
	mr.FastForward(31 * time.Minute)

	count, err := store.RecordFailure(ctx, "user@example.com", 10*time.Minute)
	if err != nil {
		t.Fatalf("RecordFailure: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected count 1 after lock cleared failures, got %d", count)
	}
}
