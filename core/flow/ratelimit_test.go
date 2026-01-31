package flow

import (
	"context"
	"testing"
	"time"
)

func TestMemoryRateLimiter(t *testing.T) {
	limiter := NewMemoryRateLimiter()
	ctx := context.Background()

	// Test basic rate limiting
	key := "test-user"
	limit := 3
	window := time.Second

	// First 3 requests should be allowed
	for i := 0; i < limit; i++ {
		allowed, remaining, err := limiter.Allow(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
		expectedRemaining := limit - i - 1
		if remaining != expectedRemaining {
			t.Errorf("Expected remaining %d, got %d", expectedRemaining, remaining)
		}
	}

	// 4th request should be denied
	allowed, remaining, err := limiter.Allow(ctx, key, limit, window)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if allowed {
		t.Error("4th request should be denied")
	}
	if remaining != 0 {
		t.Errorf("Expected remaining 0, got %d", remaining)
	}

	// After window expires, should be allowed again
	time.Sleep(window + 100*time.Millisecond)

	allowed, _, err = limiter.Allow(ctx, key, limit, window)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if !allowed {
		t.Error("Request should be allowed after window expires")
	}
}

func TestMemoryRateLimiter_Reset(t *testing.T) {
	limiter := NewMemoryRateLimiter()
	ctx := context.Background()

	key := "test-user"
	limit := 2
	window := time.Minute

	// Exhaust the limit
	for i := 0; i < limit; i++ {
		limiter.Allow(ctx, key, limit, window)
	}

	// Should be rate limited
	allowed, _, _ := limiter.Allow(ctx, key, limit, window)
	if allowed {
		t.Error("Should be rate limited")
	}

	// Reset
	err := limiter.Reset(ctx, key)
	if err != nil {
		t.Fatalf("Reset failed: %v", err)
	}

	// Should be allowed again
	allowed, _, _ = limiter.Allow(ctx, key, limit, window)
	if !allowed {
		t.Error("Should be allowed after reset")
	}
}

func TestFixedWindowRateLimiter(t *testing.T) {
	limiter := NewFixedWindowRateLimiter()
	ctx := context.Background()

	key := "test-user"
	limit := 5
	window := time.Second

	// First 5 requests should be allowed
	for i := 0; i < limit; i++ {
		allowed, _, err := limiter.Allow(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// 6th request should be denied
	allowed, _, _ := limiter.Allow(ctx, key, limit, window)
	if allowed {
		t.Error("6th request should be denied")
	}
}

func TestTokenBucketRateLimiter(t *testing.T) {
	limiter := NewTokenBucketRateLimiter()
	ctx := context.Background()

	key := "test-user"
	limit := 3
	window := time.Second

	// First requests up to limit should be allowed
	for i := 0; i < limit; i++ {
		allowed, _, err := limiter.Allow(ctx, key, limit, window)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if !allowed {
			t.Errorf("Request %d should be allowed", i+1)
		}
	}

	// Next request should be denied
	allowed, _, _ := limiter.Allow(ctx, key, limit, window)
	if allowed {
		t.Error("Request should be denied when bucket is empty")
	}

	// Wait for tokens to refill
	time.Sleep(window)

	// Should have tokens again
	allowed, _, _ = limiter.Allow(ctx, key, limit, window)
	if !allowed {
		t.Error("Request should be allowed after refill")
	}
}

func TestRateLimitError(t *testing.T) {
	err := &RateLimitError{
		RetryAfter: 5 * time.Second,
		Remaining:  0,
	}

	if !IsRateLimitError(err) {
		t.Error("Should be identified as rate limit error")
	}

	expectedMsg := "rate limit exceeded, retry after 5s"
	if err.Error() != expectedMsg {
		t.Errorf("Expected message '%s', got '%s'", expectedMsg, err.Error())
	}
}

func TestIPKeyFunc(t *testing.T) {
	keyFunc := IPKeyFunc(":")
	ctx := context.Background()

	tests := []struct {
		input    string
		expected string
	}{
		{"user@example.com:192.168.1.1", "192.168.1.1"},
		{"192.168.1.1", "192.168.1.1"},
		{"user:ip:127.0.0.1", "127.0.0.1"},
	}

	for _, tt := range tests {
		result := keyFunc(ctx, tt.input)
		if result != tt.expected {
			t.Errorf("IPKeyFunc(%s) = %s, expected %s", tt.input, result, tt.expected)
		}
	}
}
