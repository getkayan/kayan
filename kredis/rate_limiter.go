package kredis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Compile-time interface check.
var _ rateLimiter = (*RedisRateLimiter)(nil)

// rateLimiter mirrors flow.RateLimiter to avoid exporting the check.
type rateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, err error)
	Reset(ctx context.Context, key string) error
}

// RedisRateLimiter implements flow.RateLimiter using Redis for distributed rate limiting.
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
