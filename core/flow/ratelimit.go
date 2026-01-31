package flow

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// RateLimiter defines the interface for rate limiting implementations.
type RateLimiter interface {
	// Allow checks if the request should be allowed based on the key and rate limit.
	// Returns true if allowed, false if rate limited.
	// remaining indicates how many requests are left in the current window.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, remaining int, err error)

	// Reset clears the rate limit counter for the given key.
	Reset(ctx context.Context, key string) error
}

// RateLimitInfo contains information about a rate limit check.
type RateLimitInfo struct {
	Key        string
	Identifier string
	Limit      int
	Window     time.Duration
	Remaining  int
	Allowed    bool
	RetryAfter time.Duration
}

// RateLimitHooks provides extension points for customizing rate limit behavior.
type RateLimitHooks struct {
	// OnAllow is called when a request is allowed.
	// Return error to reject the request even if the rate limiter allowed it.
	OnAllow func(ctx context.Context, info *RateLimitInfo) error

	// OnDeny is called when a request is denied by rate limiting.
	// This is informational - the request will still be denied.
	// Use to log, alert, or perform custom actions.
	OnDeny func(ctx context.Context, info *RateLimitInfo)

	// OnError is called when the rate limiter encounters an error.
	// Return a new error to override the default behavior.
	// Return nil to fail open (allow the request despite error).
	OnError func(ctx context.Context, err error, info *RateLimitInfo) error

	// CreateError allows customizing the error returned when rate limited.
	// If nil, returns RateLimitError.
	CreateError func(info *RateLimitInfo) error
}

// RateLimitConfig holds configuration for the rate limiter decorator.
type RateLimitConfig struct {
	// Limit is the maximum number of requests allowed in the window.
	Limit int

	// Window is the time window for the rate limit.
	Window time.Duration

	// KeyFunc extracts the rate limit key from the identifier.
	// If nil, the identifier itself is used as the key.
	// Receives context for access to request metadata.
	KeyFunc func(ctx context.Context, identifier string) string

	// DynamicLimit allows per-request limit customization.
	// If set, overrides the static Limit value.
	// Useful for tiered rate limits (e.g., premium users get higher limits).
	DynamicLimit func(ctx context.Context, identifier string) (limit int, window time.Duration)

	// SkipFunc determines if rate limiting should be skipped for this request.
	// Return true to bypass rate limiting entirely.
	SkipFunc func(ctx context.Context, identifier string) bool

	// FailOpen determines behavior when rate limiter errors occur.
	// If true, allow requests when rate limiter fails.
	// If false (default), deny requests when rate limiter fails.
	FailOpen bool

	// Hooks for customizing behavior at various points.
	Hooks RateLimitHooks
}

// RateLimitStrategy is a decorator that adds rate limiting to any LoginStrategy.
type RateLimitStrategy struct {
	next    LoginStrategy
	limiter RateLimiter
	config  RateLimitConfig
}

// NewRateLimitStrategy creates a new rate limiting decorator.
func NewRateLimitStrategy(next LoginStrategy, limiter RateLimiter, config RateLimitConfig) *RateLimitStrategy {
	return &RateLimitStrategy{
		next:    next,
		limiter: limiter,
		config:  config,
	}
}

func (s *RateLimitStrategy) ID() string { return s.next.ID() }

// SetHooks allows updating hooks after creation.
func (s *RateLimitStrategy) SetHooks(hooks RateLimitHooks) {
	s.config.Hooks = hooks
}

// SetKeyFunc allows updating the key function after creation.
func (s *RateLimitStrategy) SetKeyFunc(fn func(ctx context.Context, identifier string) string) {
	s.config.KeyFunc = fn
}

// SetSkipFunc allows updating the skip function after creation.
func (s *RateLimitStrategy) SetSkipFunc(fn func(ctx context.Context, identifier string) bool) {
	s.config.SkipFunc = fn
}

// SetDynamicLimit allows updating the dynamic limit function after creation.
func (s *RateLimitStrategy) SetDynamicLimit(fn func(ctx context.Context, identifier string) (int, time.Duration)) {
	s.config.DynamicLimit = fn
}

func (s *RateLimitStrategy) checkRateLimit(ctx context.Context, identifier string) error {
	// Check if we should skip rate limiting
	if s.config.SkipFunc != nil && s.config.SkipFunc(ctx, identifier) {
		return nil
	}

	// Determine key
	key := identifier
	if s.config.KeyFunc != nil {
		key = s.config.KeyFunc(ctx, identifier)
	}

	// Determine limit and window
	limit := s.config.Limit
	window := s.config.Window
	if s.config.DynamicLimit != nil {
		limit, window = s.config.DynamicLimit(ctx, identifier)
	}

	// Build info for hooks
	info := &RateLimitInfo{
		Key:        key,
		Identifier: identifier,
		Limit:      limit,
		Window:     window,
	}

	// Check rate limit
	allowed, remaining, err := s.limiter.Allow(ctx, key, limit, window)
	info.Remaining = remaining
	info.Allowed = allowed

	if err != nil {
		// Rate limiter error
		if s.config.Hooks.OnError != nil {
			err = s.config.Hooks.OnError(ctx, err, info)
			if err == nil {
				// Hook chose to fail open
				return nil
			}
			return err
		}

		if s.config.FailOpen {
			return nil
		}
		return fmt.Errorf("rate limit check failed: %w", err)
	}

	if !allowed {
		info.RetryAfter = window

		// Call OnDeny hook
		if s.config.Hooks.OnDeny != nil {
			s.config.Hooks.OnDeny(ctx, info)
		}

		// Create error
		if s.config.Hooks.CreateError != nil {
			return s.config.Hooks.CreateError(info)
		}
		return &RateLimitError{
			RetryAfter: window,
			Remaining:  remaining,
		}
	}

	// Allowed - call OnAllow hook
	if s.config.Hooks.OnAllow != nil {
		if err := s.config.Hooks.OnAllow(ctx, info); err != nil {
			return err
		}
	}

	return nil
}

func (s *RateLimitStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
	if err := s.checkRateLimit(ctx, identifier); err != nil {
		return nil, err
	}
	return s.next.Authenticate(ctx, identifier, secret)
}

// Initiate supports Initiator interface for multi-step strategies.
func (s *RateLimitStrategy) Initiate(ctx context.Context, identifier string) (any, error) {
	initiator, ok := s.next.(Initiator)
	if !ok {
		return nil, fmt.Errorf("underlying strategy does not support initiation")
	}

	if err := s.checkRateLimit(ctx, identifier); err != nil {
		return nil, err
	}

	return initiator.Initiate(ctx, identifier)
}

// RateLimitError is returned when a request is rate limited.
type RateLimitError struct {
	RetryAfter time.Duration
	Remaining  int
	Message    string // Custom message (optional)
}

func (e *RateLimitError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("rate limit exceeded, retry after %v", e.RetryAfter)
}

// IsRateLimitError checks if an error is a rate limit error.
func IsRateLimitError(err error) bool {
	_, ok := err.(*RateLimitError)
	return ok
}

// AsRateLimitError extracts RateLimitError from error if possible.
func AsRateLimitError(err error) (*RateLimitError, bool) {
	e, ok := err.(*RateLimitError)
	return e, ok
}

// ---- Configurable Rate Limiter Wrapper ----

// ConfigurableRateLimiter wraps any RateLimiter with additional callbacks.
type ConfigurableRateLimiter struct {
	inner     RateLimiter
	onRequest func(ctx context.Context, key string, limit int, window time.Duration)
	onAllow   func(ctx context.Context, key string, remaining int)
	onDeny    func(ctx context.Context, key string)
}

// NewConfigurableRateLimiter wraps a rate limiter with optional callbacks.
func NewConfigurableRateLimiter(inner RateLimiter) *ConfigurableRateLimiter {
	return &ConfigurableRateLimiter{inner: inner}
}

func (r *ConfigurableRateLimiter) OnRequest(fn func(ctx context.Context, key string, limit int, window time.Duration)) *ConfigurableRateLimiter {
	r.onRequest = fn
	return r
}

func (r *ConfigurableRateLimiter) OnAllow(fn func(ctx context.Context, key string, remaining int)) *ConfigurableRateLimiter {
	r.onAllow = fn
	return r
}

func (r *ConfigurableRateLimiter) OnDeny(fn func(ctx context.Context, key string)) *ConfigurableRateLimiter {
	r.onDeny = fn
	return r
}

func (r *ConfigurableRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	if r.onRequest != nil {
		r.onRequest(ctx, key, limit, window)
	}

	allowed, remaining, err := r.inner.Allow(ctx, key, limit, window)

	if err == nil {
		if allowed && r.onAllow != nil {
			r.onAllow(ctx, key, remaining)
		} else if !allowed && r.onDeny != nil {
			r.onDeny(ctx, key)
		}
	}

	return allowed, remaining, err
}

func (r *ConfigurableRateLimiter) Reset(ctx context.Context, key string) error {
	return r.inner.Reset(ctx, key)
}

// ---- Sliding Window Rate Limiter (Memory) ----

type slidingWindowEntry struct {
	timestamps []time.Time
	mu         sync.Mutex
}

// MemoryRateLimiter implements rate limiting using in-memory sliding window.
// For production, use Redis-based implementation.
type MemoryRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*slidingWindowEntry
}

// NewMemoryRateLimiter creates a new memory-based rate limiter.
func NewMemoryRateLimiter() *MemoryRateLimiter {
	return &MemoryRateLimiter{
		entries: make(map[string]*slidingWindowEntry),
	}
}

func (r *MemoryRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	r.mu.Lock()
	entry, exists := r.entries[key]
	if !exists {
		entry = &slidingWindowEntry{}
		r.entries[key] = entry
	}
	r.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-window)

	// Remove expired timestamps
	validTimestamps := make([]time.Time, 0, len(entry.timestamps))
	for _, ts := range entry.timestamps {
		if ts.After(cutoff) {
			validTimestamps = append(validTimestamps, ts)
		}
	}
	entry.timestamps = validTimestamps

	// Check if within limit
	if len(entry.timestamps) >= limit {
		remaining := 0
		return false, remaining, nil
	}

	// Add current request
	entry.timestamps = append(entry.timestamps, now)
	remaining := limit - len(entry.timestamps)

	return true, remaining, nil
}

func (r *MemoryRateLimiter) Reset(ctx context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
	return nil
}

// ---- Fixed Window Rate Limiter (Memory) ----

type fixedWindowEntry struct {
	count     int
	expiresAt time.Time
}

// FixedWindowRateLimiter implements rate limiting using fixed time windows.
type FixedWindowRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*fixedWindowEntry
}

// NewFixedWindowRateLimiter creates a new fixed window rate limiter.
func NewFixedWindowRateLimiter() *FixedWindowRateLimiter {
	return &FixedWindowRateLimiter{
		entries: make(map[string]*fixedWindowEntry),
	}
}

func (r *FixedWindowRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	entry, exists := r.entries[key]

	// Check if window expired or doesn't exist
	if !exists || now.After(entry.expiresAt) {
		r.entries[key] = &fixedWindowEntry{
			count:     1,
			expiresAt: now.Add(window),
		}
		return true, limit - 1, nil
	}

	// Check if within limit
	if entry.count >= limit {
		return false, 0, nil
	}

	entry.count++
	remaining := limit - entry.count

	return true, remaining, nil
}

func (r *FixedWindowRateLimiter) Reset(ctx context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
	return nil
}

// ---- Token Bucket Rate Limiter (Memory) ----

type tokenBucketEntry struct {
	tokens    float64
	lastCheck time.Time
	mu        sync.Mutex
}

// TokenBucketRateLimiter implements rate limiting using token bucket algorithm.
// Allows for burst capacity while maintaining a steady rate.
type TokenBucketRateLimiter struct {
	mu      sync.Mutex
	entries map[string]*tokenBucketEntry
}

// NewTokenBucketRateLimiter creates a new token bucket rate limiter.
func NewTokenBucketRateLimiter() *TokenBucketRateLimiter {
	return &TokenBucketRateLimiter{
		entries: make(map[string]*tokenBucketEntry),
	}
}

func (r *TokenBucketRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, int, error) {
	r.mu.Lock()
	entry, exists := r.entries[key]
	if !exists {
		entry = &tokenBucketEntry{
			tokens:    float64(limit),
			lastCheck: time.Now(),
		}
		r.entries[key] = entry
	}
	r.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(entry.lastCheck)
	entry.lastCheck = now

	// Refill tokens based on elapsed time
	// Rate = limit tokens per window
	refillRate := float64(limit) / window.Seconds()
	entry.tokens += refillRate * elapsed.Seconds()

	// Cap at max tokens
	if entry.tokens > float64(limit) {
		entry.tokens = float64(limit)
	}

	// Check if we have a token available
	if entry.tokens < 1 {
		return false, 0, nil
	}

	// Consume a token
	entry.tokens--
	remaining := int(entry.tokens)

	return true, remaining, nil
}

func (r *TokenBucketRateLimiter) Reset(ctx context.Context, key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, key)
	return nil
}

// ---- Key Function Helpers ----

// IPKeyFunc creates a key function that extracts IP from identifier.
// Useful when identifier contains "email:ip" format.
func IPKeyFunc(separator string) func(context.Context, string) string {
	return func(_ context.Context, identifier string) string {
		// Try to split by separator to get IP portion
		for i := len(identifier) - 1; i >= 0; i-- {
			if string(identifier[i]) == separator {
				return identifier[i+1:]
			}
		}
		return identifier
	}
}

// PrefixKeyFunc adds a prefix to keys for namespacing.
func PrefixKeyFunc(prefix string) func(context.Context, string) string {
	return func(_ context.Context, identifier string) string {
		return prefix + identifier
	}
}

// CompositeKeyFunc chains multiple key functions.
func CompositeKeyFunc(fns ...func(context.Context, string) string) func(context.Context, string) string {
	return func(ctx context.Context, identifier string) string {
		result := identifier
		for _, fn := range fns {
			result = fn(ctx, result)
		}
		return result
	}
}

// ContextKeyFunc extracts additional context from ctx to build the key.
type ContextKey string

func ContextKeyFunc(ctxKey ContextKey, separator string) func(context.Context, string) string {
	return func(ctx context.Context, identifier string) string {
		if val := ctx.Value(ctxKey); val != nil {
			return fmt.Sprintf("%s%s%v", identifier, separator, val)
		}
		return identifier
	}
}
