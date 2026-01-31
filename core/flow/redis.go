package flow

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisLockoutStore implements LockoutStore using Redis for distributed deployments.
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

// ---- Redis Rate Limiter ----

// RedisRateLimiter implements RateLimiter using Redis for distributed rate limiting.
type RedisRateLimiter struct {
	client *redis.Client
	prefix string
}

// NewRedisRateLimiter creates a new Redis-based rate limiter.
func NewRedisRateLimiter(client *redis.Client, prefix string) *RedisRateLimiter {
	if prefix == "" {
		prefix = "kayan:ratelimit:"
	}
	return &RedisRateLimiter{
		client: client,
		prefix: prefix,
	}
}

func (r *RedisRateLimiter) key(k string) string {
	return r.prefix + k
}

// Allow checks if the request should be allowed using sliding window log algorithm.
func (r *RedisRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	redisKey := r.key(key)
	now := time.Now()
	windowStart := now.Add(-window)

	// Use Lua script for atomic operations
	script := redis.NewScript(`
		local key = KEYS[1]
		local now = tonumber(ARGV[1])
		local window_start = tonumber(ARGV[2])
		local limit = tonumber(ARGV[3])
		local window_ms = tonumber(ARGV[4])
		
		-- Remove old entries outside the window
		redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
		
		-- Count current entries
		local count = redis.call('ZCARD', key)
		
		if count >= limit then
			return {0, 0}
		end
		
		-- Add current request
		redis.call('ZADD', key, now, now .. ':' .. math.random())
		redis.call('PEXPIRE', key, window_ms)
		
		local remaining = limit - count - 1
		return {1, remaining}
	`)

	result, err := script.Run(ctx, r.client, []string{redisKey},
		now.UnixMilli(),
		windowStart.UnixMilli(),
		limit,
		window.Milliseconds(),
	).Result()

	if err != nil {
		return false, 0, fmt.Errorf("redis rate limit: allow check failed: %w", err)
	}

	arr, ok := result.([]interface{})
	if !ok || len(arr) != 2 {
		return false, 0, fmt.Errorf("redis rate limit: unexpected result format")
	}

	allowed := arr[0].(int64) == 1
	remaining := int(arr[1].(int64))

	return allowed, remaining, nil
}

// Reset clears the rate limit counter for the given key.
func (r *RedisRateLimiter) Reset(ctx context.Context, key string) error {
	redisKey := r.key(key)
	if err := r.client.Del(ctx, redisKey).Err(); err != nil {
		return fmt.Errorf("redis rate limit: reset failed: %w", err)
	}
	return nil
}

// ---- Redis WebAuthn Session Store ----

// RedisWebAuthnSessionStore implements WebAuthnSessionStore using Redis.
type RedisWebAuthnSessionStore struct {
	client *redis.Client
	prefix string
}

// NewRedisWebAuthnSessionStore creates a new Redis-based WebAuthn session store.
func NewRedisWebAuthnSessionStore(client *redis.Client, prefix string) *RedisWebAuthnSessionStore {
	if prefix == "" {
		prefix = "kayan:webauthn:session:"
	}
	return &RedisWebAuthnSessionStore{
		client: client,
		prefix: prefix,
	}
}

func (s *RedisWebAuthnSessionStore) key(sessionID string) string {
	return s.prefix + sessionID
}

func (s *RedisWebAuthnSessionStore) SaveSession(ctx context.Context, sessionID string, data *WebAuthnSessionData) error {
	key := s.key(sessionID)
	ttl := time.Until(data.ExpiresAt)
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}

	// Serialize the data
	fields := map[string]interface{}{
		"challenge":         data.Challenge,
		"user_id":           string(data.UserID),
		"user_verification": data.UserVerification,
		"expires_at":        data.ExpiresAt.Unix(),
	}

	pipe := s.client.Pipeline()
	pipe.HSet(ctx, key, fields)
	pipe.Expire(ctx, key, ttl)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("redis webauthn: save session failed: %w", err)
	}

	// Store allowed credential IDs if present
	if len(data.AllowedCredIDs) > 0 {
		credKey := key + ":creds"
		for i, cred := range data.AllowedCredIDs {
			s.client.HSet(ctx, credKey, fmt.Sprintf("%d", i), string(cred))
		}
		s.client.Expire(ctx, credKey, ttl)
	}

	return nil
}

func (s *RedisWebAuthnSessionStore) GetSession(ctx context.Context, sessionID string) (*WebAuthnSessionData, error) {
	key := s.key(sessionID)

	result, err := s.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("redis webauthn: get session failed: %w", err)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("session not found")
	}

	var expiresAt int64
	fmt.Sscanf(result["expires_at"], "%d", &expiresAt)

	data := &WebAuthnSessionData{
		Challenge:        result["challenge"],
		UserID:           []byte(result["user_id"]),
		UserVerification: result["user_verification"],
		ExpiresAt:        time.Unix(expiresAt, 0),
	}

	// Get allowed credential IDs if present
	credKey := key + ":creds"
	creds, err := s.client.HGetAll(ctx, credKey).Result()
	if err == nil && len(creds) > 0 {
		for i := 0; i < len(creds); i++ {
			if val, ok := creds[fmt.Sprintf("%d", i)]; ok {
				data.AllowedCredIDs = append(data.AllowedCredIDs, []byte(val))
			}
		}
	}

	return data, nil
}

func (s *RedisWebAuthnSessionStore) DeleteSession(ctx context.Context, sessionID string) error {
	key := s.key(sessionID)
	credKey := key + ":creds"

	pipe := s.client.Pipeline()
	pipe.Del(ctx, key)
	pipe.Del(ctx, credKey)
	_, err := pipe.Exec(ctx)

	if err != nil {
		return fmt.Errorf("redis webauthn: delete session failed: %w", err)
	}
	return nil
}
