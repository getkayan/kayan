package flow

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Mock Strategy that we can control
type mockAuthStrategy struct {
	shouldFail bool
}

func (m *mockAuthStrategy) ID() string { return "mock" }
func (m *mockAuthStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
	if m.shouldFail {
		return nil, fmt.Errorf("invalid password")
	}
	return "user-identity", nil
}

func TestLockoutFlow(t *testing.T) {
	store := NewMemoryLockoutStore()
	mock := &mockAuthStrategy{shouldFail: true}

	// Max 3 failures, 1 second lockout
	strategy := NewLockoutStrategy(mock, store, 3, 1*time.Second, 10*time.Minute)

	ctx := context.Background()
	user := "hacker@example.com"

	// 1. Fail 3 times
	for i := 0; i < 3; i++ {
		_, err := strategy.Authenticate(ctx, user, "badpass")
		if err == nil {
			t.Errorf("Expected error on attempt %d", i)
		}
	}

	// 2. 4th attempt should be LOCKED immediately (store checks BEFORE calling next)
	// We verify this by ensuring IsLocked returns true
	locked, _, _ := store.IsLocked(ctx, user)
	if !locked {
		t.Error("Account should be locked after 3 failures")
	}

	// And Authenticate calls should fail with specific message
	_, err := strategy.Authenticate(ctx, user, "badpass")
	if err == nil {
		t.Error("Expected error when locked")
	} else if len(err.Error()) < 6 || err.Error()[:6] != "accoun" { // "account is locked..."
		t.Errorf("Expected lockout error, got: %v", err)
	}

	// 3. Wait for expiry
	time.Sleep(1100 * time.Millisecond)

	// 4. Should be unlocked
	locked, _, _ = store.IsLocked(ctx, user)
	if locked {
		t.Error("Account should be unlocked after duration")
	}

	// 5. Successful login should clear failures
	mock.shouldFail = false
	_, err = strategy.Authenticate(ctx, user, "goodpass")
	if err != nil {
		t.Errorf("Expected success, got: %v", err)
	}

	// Check Failures Cleared (internal check)
	record := store.getRecord(user)
	if record.failures != 0 {
		t.Errorf("Failures should be 0 after success, got %d", record.failures)
	}
}

func TestLockout_FailOpen(t *testing.T) {
	mock := &mockAuthStrategy{shouldFail: false}

	// Use an error-returning store
	errStore := &errorLockoutStore{}

	config := LockoutConfig{
		MaxFailures:     3,
		LockoutDuration: 5 * time.Minute,
		FailureWindow:   10 * time.Minute,
		FailOpen:        true,
	}
	strategy := NewLockoutStrategyWithConfig(mock, errStore, config)

	ctx := context.Background()
	// Despite store errors, FailOpen=true should allow authentication
	result, err := strategy.Authenticate(ctx, "user@example.com", "goodpass")
	if err != nil {
		t.Fatalf("expected FailOpen to allow auth despite store error, got: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestLockout_FailClosed(t *testing.T) {
	mock := &mockAuthStrategy{shouldFail: false}

	errStore := &errorLockoutStore{}

	config := LockoutConfig{
		MaxFailures:     3,
		LockoutDuration: 5 * time.Minute,
		FailureWindow:   10 * time.Minute,
		FailOpen:        false,
	}
	strategy := NewLockoutStrategyWithConfig(mock, errStore, config)

	ctx := context.Background()
	_, err := strategy.Authenticate(ctx, "user@example.com", "goodpass")
	if err == nil {
		t.Error("expected FailOpen=false to deny auth on store error")
	}
}

func TestLockout_Hooks_OnLocked(t *testing.T) {
	store := NewMemoryLockoutStore()
	mock := &mockAuthStrategy{shouldFail: true}

	var onLockedCalled bool
	var lockedIdentifier string

	config := LockoutConfig{
		MaxFailures:     2,
		LockoutDuration: 5 * time.Minute,
		FailureWindow:   10 * time.Minute,
		Hooks: LockoutHooks{
			OnLocked: func(ctx context.Context, info *LockoutInfo) {
				onLockedCalled = true
				lockedIdentifier = info.Identifier
			},
		},
	}
	strategy := NewLockoutStrategyWithConfig(mock, store, config)

	ctx := context.Background()
	// Fail twice to trigger lockout
	strategy.Authenticate(ctx, "victim@example.com", "bad")
	strategy.Authenticate(ctx, "victim@example.com", "bad")

	if !onLockedCalled {
		t.Error("expected OnLocked hook to be called")
	}
	if lockedIdentifier != "victim@example.com" {
		t.Errorf("expected identifier victim@example.com, got %s", lockedIdentifier)
	}
}

func TestLockout_WithConfig(t *testing.T) {
	store := NewMemoryLockoutStore()
	mock := &mockAuthStrategy{shouldFail: true}

	config := LockoutConfig{
		MaxFailures:     5,
		LockoutDuration: 30 * time.Minute,
		FailureWindow:   15 * time.Minute,
	}
	strategy := NewLockoutStrategyWithConfig(mock, store, config)

	ctx := context.Background()
	user := "test@example.com"

	// Should NOT be locked after 4 failures (max is 5)
	for i := 0; i < 4; i++ {
		strategy.Authenticate(ctx, user, "bad")
	}

	locked, _, _ := store.IsLocked(ctx, user)
	if locked {
		t.Error("should not be locked after only 4 failures (max=5)")
	}

	// 5th failure should trigger lockout
	strategy.Authenticate(ctx, user, "bad")
	locked, _, _ = store.IsLocked(ctx, user)
	if !locked {
		t.Error("should be locked after 5 failures")
	}
}

func TestLockout_Hooks_OnUnlocked(t *testing.T) {
	store := NewMemoryLockoutStore()
	mock := &mockAuthStrategy{shouldFail: true}

	var onUnlockedIdentifier string

	config := LockoutConfig{
		MaxFailures:     2,
		LockoutDuration: 5 * time.Minute,
		FailureWindow:   10 * time.Minute,
		Hooks: LockoutHooks{
			OnUnlocked: func(ctx context.Context, identifier string) {
				onUnlockedIdentifier = identifier
			},
		},
	}
	strategy := NewLockoutStrategyWithConfig(mock, store, config)

	ctx := context.Background()
	// Fail once
	strategy.Authenticate(ctx, "user@test.com", "bad")

	// Then succeed
	mock.shouldFail = false
	strategy.Authenticate(ctx, "user@test.com", "good")

	if onUnlockedIdentifier != "user@test.com" {
		t.Errorf("expected OnUnlocked hook with user@test.com, got %q", onUnlockedIdentifier)
	}
}

// errorLockoutStore always returns errors, for testing FailOpen behavior.
type errorLockoutStore struct{}

func (s *errorLockoutStore) RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error) {
	return 0, fmt.Errorf("store error")
}
func (s *errorLockoutStore) ClearFailures(ctx context.Context, identifier string) error {
	return fmt.Errorf("store error")
}
func (s *errorLockoutStore) Lock(ctx context.Context, identifier string, duration time.Duration) error {
	return fmt.Errorf("store error")
}
func (s *errorLockoutStore) IsLocked(ctx context.Context, identifier string) (bool, time.Time, error) {
	return false, time.Time{}, fmt.Errorf("store error")
}

func TestLockout_ConcurrentAuthenticate(t *testing.T) {
	store := NewMemoryLockoutStore()
	mock := &mockAuthStrategy{shouldFail: false}
	strategy := NewLockoutStrategy(mock, store, 5, 1*time.Second, 10*time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = strategy.Authenticate(context.Background(), "user@example.com", "pass")
		}()
	}
	wg.Wait()
}

func TestLockout_ConcurrentSetHooks(t *testing.T) {
	store := NewMemoryLockoutStore()
	mock := &mockAuthStrategy{shouldFail: false}
	strategy := NewLockoutStrategy(mock, store, 5, 1*time.Second, 10*time.Minute)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			strategy.SetHooks(LockoutHooks{})
		}()
		go func() {
			defer wg.Done()
			_, _ = strategy.Authenticate(context.Background(), "user@example.com", "pass")
		}()
	}
	wg.Wait()
}
