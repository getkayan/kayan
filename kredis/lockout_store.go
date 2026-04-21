package kredis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Compile-time interface check.
var _ lockoutStore = (*RedisLockoutStore)(nil)

// lockoutStore mirrors flow.LockoutStore to avoid exporting the check.
type lockoutStore interface {
	RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error)
	ClearFailures(ctx context.Context, identifier string) error
	Lock(ctx context.Context, identifier string, duration time.Duration) error
	IsLocked(ctx context.Context, identifier string) (bool, time.Time, error)
}

// RedisLockoutStore implements flow.LockoutStore using Redis for distributed deployments.
type RedisLockoutStore struct {
	client *redis.Client
	prefix string
}

// NewRedisLockoutStore creates a new Redis-based lockout store.
func NewRedisLockoutStore(client *redis.Client, prefix string) *RedisLockoutStore {
	if prefix == "" {
		prefix = "kayan:lockout:"
	}
	return &RedisLockoutStore{
		client: client,
		prefix: prefix,
	}
}

func (s *RedisLockoutStore) failureKey(identifier string) string {
	return s.prefix + "failures:" + identifier
}

func (s *RedisLockoutStore) lockKey(identifier string) string {
	return s.prefix + "locked:" + identifier
}

// RecordFailure increments the failure count for the identifier.
func (s *RedisLockoutStore) RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error) {
	key := s.failureKey(identifier)

	// Use a Lua script for atomic increment + expire
	script := redis.NewScript(`
		local count = redis.call('INCR', KEYS[1])
		if count == 1 then
			redis.call('PEXPIRE', KEYS[1], ARGV[1])
		end
		return count
	`)

	result, err := script.Run(ctx, s.client, []string{key}, ttl.Milliseconds()).Result()
	if err != nil {
		return 0, fmt.Errorf("redis lockout: record failure failed: %w", err)
	}

	count, ok := result.(int64)
	if !ok {
		return 0, fmt.Errorf("redis lockout: unexpected result type")
	}

	return int(count), nil
}

// ClearFailures resets the failure count for the identifier.
func (s *RedisLockoutStore) ClearFailures(ctx context.Context, identifier string) error {
	key := s.failureKey(identifier)
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("redis lockout: clear failures failed: %w", err)
	}
	return nil
}

// Lock manually locks the identifier for the given duration.
func (s *RedisLockoutStore) Lock(ctx context.Context, identifier string, duration time.Duration) error {
	key := s.lockKey(identifier)
	lockedUntil := time.Now().Add(duration).Unix()

	if err := s.client.Set(ctx, key, lockedUntil, duration).Err(); err != nil {
		return fmt.Errorf("redis lockout: lock failed: %w", err)
	}

	// Clear the failure count on lock
	s.ClearFailures(ctx, identifier)

	return nil
}

// IsLocked checks if the identifier is currently locked.
func (s *RedisLockoutStore) IsLocked(ctx context.Context, identifier string) (bool, time.Time, error) {
	key := s.lockKey(identifier)

	result, err := s.client.Get(ctx, key).Result()
	if err == redis.Nil {
		return false, time.Time{}, nil
	}
	if err != nil {
		return false, time.Time{}, fmt.Errorf("redis lockout: check lock failed: %w", err)
	}

	var lockedUntil int64
	if _, err := fmt.Sscanf(result, "%d", &lockedUntil); err != nil {
		return false, time.Time{}, fmt.Errorf("redis lockout: parse lock time failed: %w", err)
	}

	until := time.Unix(lockedUntil, 0)
	if time.Now().After(until) {
		// Key should have expired, but just in case
		s.client.Del(ctx, key)
		return false, time.Time{}, nil
	}

	return true, until, nil
}
