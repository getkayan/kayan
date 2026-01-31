package flow

import (
	"context"
	"fmt"
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
