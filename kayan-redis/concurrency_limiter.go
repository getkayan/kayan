package redisstore

import (
	"context"
	"fmt"
	"time"

	"github.com/getkayan/kayan/core/tenant"
	"github.com/redis/go-redis/v9"
)

var _ tenant.ConcurrencyLimiter = (*RedisConcurrencyLimiter)(nil)

var acquireConcurrencyScript = redis.NewScript(`
local key = KEYS[1]
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = tonumber(ARGV[1])
local expires_at = now + ttl
local limit = tonumber(ARGV[2])
local token = ARGV[3]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
local count = redis.call('ZCARD', key)
if count >= limit then
    local earliest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local retry_after = 0
    if #earliest == 2 then
        retry_after = math.max(0, tonumber(earliest[2]) - now)
    end
    return {0, retry_after, 0}
end

redis.call('ZADD', key, expires_at, token)
local latest = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
if #latest == 2 then
    redis.call('PEXPIREAT', key, math.floor(tonumber(latest[2])))
end
return {1, 0, expires_at}
`)

var renewConcurrencyScript = redis.NewScript(`
local key = KEYS[1]
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local ttl = tonumber(ARGV[1])
local expires_at = now + ttl
local token = ARGV[2]

redis.call('ZREMRANGEBYSCORE', key, '-inf', now)
if not redis.call('ZSCORE', key, token) then
    return {0, 0}
end
redis.call('ZADD', key, 'XX', expires_at, token)
local latest = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
if #latest == 2 then
    redis.call('PEXPIREAT', key, math.floor(tonumber(latest[2])))
end
return {1, expires_at}
`)

var releaseConcurrencyScript = redis.NewScript(`
local key = KEYS[1]
local token = ARGV[1]

redis.call('ZREM', key, token)
if redis.call('ZCARD', key) == 0 then
    redis.call('DEL', key)
    return 1
end
local latest = redis.call('ZREVRANGE', key, 0, 0, 'WITHSCORES')
if #latest == 2 then
    redis.call('PEXPIREAT', key, math.floor(tonumber(latest[2])))
end
return 1
`)

// RedisConcurrencyLimiter enforces distributed in-flight limits with expiring
// sorted-set leases. Lua scripts make pruning, counting, and reservation one
// atomic operation across every application replica.
type RedisConcurrencyLimiter struct {
	client *redis.Client
	prefix string
}

// NewRedisConcurrencyLimiter creates a distributed concurrency limiter.
func NewRedisConcurrencyLimiter(client *redis.Client, prefix string) *RedisConcurrencyLimiter {
	if prefix == "" {
		prefix = "kayan:concurrency:"
	}
	return &RedisConcurrencyLimiter{client: client, prefix: prefix}
}

// Acquire reserves capacity until release or TTL expiry.
func (r *RedisConcurrencyLimiter) Acquire(ctx context.Context, key string, limit int, ttl time.Duration) (tenant.ConcurrencyLease, bool, time.Duration, error) {
	if limit <= 0 || ttl < time.Millisecond {
		return tenant.ConcurrencyLease{}, false, 0, tenant.ErrInvalidLimits
	}
	if err := ctx.Err(); err != nil {
		return tenant.ConcurrencyLease{}, false, 0, err
	}
	token, err := redisRandomToken()
	if err != nil {
		return tenant.ConcurrencyLease{}, false, 0, err
	}
	result, err := acquireConcurrencyScript.Run(ctx, r.client, []string{r.key(key)},
		ttl.Milliseconds(), limit, token).Result()
	if err != nil {
		return tenant.ConcurrencyLease{}, false, 0, fmt.Errorf("redis concurrency: acquire: %w", err)
	}
	values, ok := result.([]interface{})
	if !ok || len(values) != 3 {
		return tenant.ConcurrencyLease{}, false, 0, fmt.Errorf("redis concurrency: acquire returned %T", result)
	}
	allowed, ok := redisInt64(values[0])
	if !ok {
		return tenant.ConcurrencyLease{}, false, 0, fmt.Errorf("redis concurrency: invalid allowed result %T", values[0])
	}
	retryMillis, ok := redisInt64(values[1])
	if !ok {
		return tenant.ConcurrencyLease{}, false, 0, fmt.Errorf("redis concurrency: invalid retry result %T", values[1])
	}
	if allowed != 1 {
		return tenant.ConcurrencyLease{}, false, time.Duration(retryMillis) * time.Millisecond, nil
	}
	expiresMillis, ok := redisInt64(values[2])
	if !ok || expiresMillis <= 0 {
		return tenant.ConcurrencyLease{}, false, 0, fmt.Errorf("redis concurrency: invalid expiry result %T", values[2])
	}
	expiresAt := time.UnixMilli(expiresMillis)
	return tenant.ConcurrencyLease{Key: key, Token: token, ExpiresAt: expiresAt}, true, 0, nil
}

// Renew extends a lease only when its ownership token still exists.
func (r *RedisConcurrencyLimiter) Renew(ctx context.Context, lease tenant.ConcurrencyLease, ttl time.Duration) (tenant.ConcurrencyLease, bool, error) {
	if ttl < time.Millisecond {
		return tenant.ConcurrencyLease{}, false, tenant.ErrInvalidLimits
	}
	if err := ctx.Err(); err != nil {
		return tenant.ConcurrencyLease{}, false, err
	}
	result, err := renewConcurrencyScript.Run(ctx, r.client, []string{r.key(lease.Key)},
		ttl.Milliseconds(), lease.Token).Result()
	if err != nil {
		return tenant.ConcurrencyLease{}, false, fmt.Errorf("redis concurrency: renew: %w", err)
	}
	values, ok := result.([]interface{})
	if !ok || len(values) != 2 {
		return tenant.ConcurrencyLease{}, false, fmt.Errorf("redis concurrency: invalid renew result %T", result)
	}
	renewed, ok := redisInt64(values[0])
	if !ok {
		return tenant.ConcurrencyLease{}, false, fmt.Errorf("redis concurrency: invalid renewed result %T", values[0])
	}
	if renewed != 1 {
		return tenant.ConcurrencyLease{}, false, nil
	}
	expiresMillis, ok := redisInt64(values[1])
	if !ok || expiresMillis <= 0 {
		return tenant.ConcurrencyLease{}, false, fmt.Errorf("redis concurrency: invalid renew expiry result %T", values[1])
	}
	lease.ExpiresAt = time.UnixMilli(expiresMillis)
	return lease, true, nil
}

// Release removes only the lease with the matching ownership token. It is
// idempotent, so cleanup after a timeout or retry is safe.
func (r *RedisConcurrencyLimiter) Release(ctx context.Context, lease tenant.ConcurrencyLease) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := releaseConcurrencyScript.Run(ctx, r.client, []string{r.key(lease.Key)}, lease.Token).Result(); err != nil {
		return fmt.Errorf("redis concurrency: release: %w", err)
	}
	return nil
}

func (r *RedisConcurrencyLimiter) key(key string) string {
	return r.prefix + key
}

func redisInt64(value interface{}) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	default:
		return 0, false
	}
}
