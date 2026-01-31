package flow

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// LockoutStore defines the storage for tracking login failures and lockouts.
type LockoutStore interface {
	// RecordFailure increments the failure count for the identifier.
	// ttl defines how long this failure record should be kept.
	RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error)

	// ClearFailures resets the failure count for the identifier.
	ClearFailures(ctx context.Context, identifier string) error

	// Lock manually locks the identifier for the given duration.
	Lock(ctx context.Context, identifier string, duration time.Duration) error

	// IsLocked checks if the identifier is currently locked.
	// Returns true and the expiry time if locked.
	IsLocked(ctx context.Context, identifier string) (bool, time.Time, error)
}

// LockoutInfo contains information about a lockout event.
type LockoutInfo struct {
	Identifier      string
	FailureCount    int
	MaxFailures     int
	LockedUntil     time.Time
	LockoutDuration time.Duration
}

// LockoutHooks provides extension points for customizing lockout behavior.
type LockoutHooks struct {
	// OnFailure is called when an authentication failure is recorded.
	// Receives the current failure count. Return error to override default behavior.
	OnFailure func(ctx context.Context, info *LockoutInfo) error

	// OnLocked is called when an account becomes locked.
	// Use for alerting, logging, or custom actions.
	OnLocked func(ctx context.Context, info *LockoutInfo)

	// OnUnlocked is called when an account is unlocked (on successful login).
	OnUnlocked func(ctx context.Context, identifier string)

	// OnLockoutCheck is called before checking if account is locked.
	// Return true, time.Time, nil to override with custom lock status.
	// Return false, _, nil to use default behavior.
	OnLockoutCheck func(ctx context.Context, identifier string) (locked bool, until time.Time, handled bool)

	// CreateLockError allows customizing the error when locked.
	CreateLockError func(info *LockoutInfo) error

	// KeyFunc extracts the lockout key from the identifier.
	// Useful for grouping by IP, tenant, etc.
	KeyFunc func(ctx context.Context, identifier string) string

	// ShouldRecordFailure determines if a failure should be counted.
	// Return false to skip recording (e.g., for certain error types).
	ShouldRecordFailure func(ctx context.Context, identifier string, err error) bool

	// ShouldClearOnSuccess determines if failures should clear on success.
	// Default is true. Set to false for accumulating counters.
	ShouldClearOnSuccess func(ctx context.Context, identifier string) bool
}

// LockoutConfig holds configuration for the lockout decorator.
type LockoutConfig struct {
	// MaxFailures is the number of failures before lockout (e.g. 5)
	MaxFailures int

	// LockoutDuration is how long to lock the account (e.g. 15 minutes)
	LockoutDuration time.Duration

	// FailureWindow is how long failures are remembered (e.g. 15 minutes)
	FailureWindow time.Duration

	// FailOpen determines behavior when store errors occur.
	// If true, allow requests when store fails. If false (default), deny.
	FailOpen bool

	// Hooks for customizing behavior.
	Hooks LockoutHooks
}

// LockoutStrategy is a decorator that adds brute-force protection to a LoginStrategy.
type LockoutStrategy struct {
	next   LoginStrategy
	store  LockoutStore
	config LockoutConfig
}

// NewLockoutStrategy creates a new lockout decorator.
func NewLockoutStrategy(next LoginStrategy, store LockoutStore, maxFailures int, lockoutDuration, failureWindow time.Duration) *LockoutStrategy {
	return &LockoutStrategy{
		next:  next,
		store: store,
		config: LockoutConfig{
			MaxFailures:     maxFailures,
			LockoutDuration: lockoutDuration,
			FailureWindow:   failureWindow,
		},
	}
}

// NewLockoutStrategyWithConfig creates a lockout decorator with full configuration.
func NewLockoutStrategyWithConfig(next LoginStrategy, store LockoutStore, config LockoutConfig) *LockoutStrategy {
	return &LockoutStrategy{
		next:   next,
		store:  store,
		config: config,
	}
}

// SetHooks allows updating hooks after creation.
func (s *LockoutStrategy) SetHooks(hooks LockoutHooks) {
	s.config.Hooks = hooks
}

func (s *LockoutStrategy) ID() string {
	return s.next.ID()
}

func (s *LockoutStrategy) getKey(ctx context.Context, identifier string) string {
	if s.config.Hooks.KeyFunc != nil {
		return s.config.Hooks.KeyFunc(ctx, identifier)
	}
	return identifier
}

func (s *LockoutStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
	key := s.getKey(ctx, identifier)

	// 1. Check if locked
	var locked bool
	var until time.Time
	var err error

	// Allow hook to override lock check
	if s.config.Hooks.OnLockoutCheck != nil {
		var handled bool
		locked, until, handled = s.config.Hooks.OnLockoutCheck(ctx, key)
		if !handled {
			locked, until, err = s.store.IsLocked(ctx, key)
		}
	} else {
		locked, until, err = s.store.IsLocked(ctx, key)
	}

	if err != nil {
		if s.config.FailOpen {
			// Continue despite error
		} else {
			return nil, fmt.Errorf("lockout check failed: %v", err)
		}
	}

	if locked {
		info := &LockoutInfo{
			Identifier:  identifier,
			LockedUntil: until,
		}
		if s.config.Hooks.CreateLockError != nil {
			return nil, s.config.Hooks.CreateLockError(info)
		}
		return nil, fmt.Errorf("account is locked until %v", until.Format(time.RFC822))
	}

	// 2. Delegate to next strategy
	res, authErr := s.next.Authenticate(ctx, identifier, secret)

	// 3. Handle Success
	if authErr == nil {
		shouldClear := true
		if s.config.Hooks.ShouldClearOnSuccess != nil {
			shouldClear = s.config.Hooks.ShouldClearOnSuccess(ctx, key)
		}
		if shouldClear {
			_ = s.store.ClearFailures(ctx, key)
			if s.config.Hooks.OnUnlocked != nil {
				s.config.Hooks.OnUnlocked(ctx, identifier)
			}
		}
		return res, nil
	}

	// 4. Handle Failure
	shouldRecord := true
	if s.config.Hooks.ShouldRecordFailure != nil {
		shouldRecord = s.config.Hooks.ShouldRecordFailure(ctx, identifier, authErr)
	}

	if !shouldRecord {
		return nil, authErr
	}

	count, rErr := s.store.RecordFailure(ctx, key, s.config.FailureWindow)
	if rErr != nil {
		return nil, authErr
	}

	info := &LockoutInfo{
		Identifier:      identifier,
		FailureCount:    count,
		MaxFailures:     s.config.MaxFailures,
		LockoutDuration: s.config.LockoutDuration,
	}

	// Call OnFailure hook
	if s.config.Hooks.OnFailure != nil {
		if hookErr := s.config.Hooks.OnFailure(ctx, info); hookErr != nil {
			return nil, hookErr
		}
	}

	if count >= s.config.MaxFailures {
		// Lock the account
		_ = s.store.Lock(ctx, key, s.config.LockoutDuration)
		info.LockedUntil = time.Now().Add(s.config.LockoutDuration)

		if s.config.Hooks.OnLocked != nil {
			s.config.Hooks.OnLocked(ctx, info)
		}
	}

	return nil, authErr
}

// Initiate supports Initiator interface for multi-step strategies.
func (s *LockoutStrategy) Initiate(ctx context.Context, identifier string) (any, error) {
	if initiator, ok := s.next.(Initiator); ok {
		return initiator.Initiate(ctx, identifier)
	}
	return nil, fmt.Errorf("underlying strategy does not support initiation")
}

// -- Memory Implementation --

type memRecord struct {
	failures    int
	failExp     time.Time
	lockedUntil time.Time
}

type MemoryLockoutStore struct {
	mu    sync.Mutex
	items map[string]*memRecord
}

func NewMemoryLockoutStore() *MemoryLockoutStore {
	return &MemoryLockoutStore{
		items: make(map[string]*memRecord),
	}
}

func (s *MemoryLockoutStore) getRecord(id string) *memRecord {
	if r, ok := s.items[id]; ok {
		return r
	}
	r := &memRecord{}
	s.items[id] = r
	return r
}

func (s *MemoryLockoutStore) RecordFailure(ctx context.Context, identifier string, ttl time.Duration) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := s.getRecord(identifier)
	now := time.Now()

	// Check expiry of existing failures
	if now.After(r.failExp) {
		r.failures = 0
	}

	r.failures++
	r.failExp = now.Add(ttl)

	// Clean up map? In a real mem store we'd need a cleaner.
	// For this simple impl, we leave records.

	return r.failures, nil
}

func (s *MemoryLockoutStore) ClearFailures(ctx context.Context, identifier string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.items, identifier)
	return nil
}

func (s *MemoryLockoutStore) Lock(ctx context.Context, identifier string, duration time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	r := s.getRecord(identifier)
	r.lockedUntil = time.Now().Add(duration)
	return nil
}

func (s *MemoryLockoutStore) IsLocked(ctx context.Context, identifier string) (bool, time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if r, ok := s.items[identifier]; ok {
		if time.Now().Before(r.lockedUntil) {
			return true, r.lockedUntil, nil
		}
	}
	return false, time.Time{}, nil
}
