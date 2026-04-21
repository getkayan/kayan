// Package kredis provides Redis-backed storage adapters for Kayan IAM.
//
// This package implements distributed versions of core/flow store interfaces
// using Redis, suitable for multi-instance deployments where in-memory stores
// are insufficient.
//
// # Implementations
//
//   - RedisLockoutStore: Implements flow.LockoutStore for distributed brute-force lockout tracking.
//   - RedisRateLimiter: Implements flow.RateLimiter for distributed rate limiting.
//   - RedisWebAuthnSessionStore: Implements flow.WebAuthnSessionStore for WebAuthn ceremony sessions.
package kredis
