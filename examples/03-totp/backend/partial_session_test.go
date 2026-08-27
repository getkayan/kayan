package main

import (
	"context"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/session"
)

// The partial tier must be able to destroy its own token. Without a revocation
// store Delete is a no-op and the pre-MFA token outlives the upgrade.
func TestPartialSessionIsDestroyable(t *testing.T) {
	strategy := session.NewHS256Strategy("test-secret-not-for-production", 5*time.Minute).
		WithRevocationStore(session.NewMemoryRevocationStore())
	ctx := context.Background()

	sess, err := strategy.Create(ctx, "partial-1", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := strategy.Delete(ctx, sess.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := strategy.Validate(ctx, sess.ID); err == nil {
		t.Error("the partial token still validates after the upgrade destroyed it")
	}
}

// Without the store, Delete cannot end it -- the shape this example had.
func TestPartialSessionWithoutStoreCannotBeDestroyed(t *testing.T) {
	strategy := session.NewHS256Strategy("test-secret-not-for-production", 5*time.Minute)
	ctx := context.Background()

	sess, err := strategy.Create(ctx, "partial-1", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := strategy.Delete(ctx, sess.ID); err == nil {
		t.Error("Delete reported success with no revocation store")
	}
}
