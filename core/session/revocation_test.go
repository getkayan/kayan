package session

import (
	"context"
	"testing"
	"time"
)

func TestMemoryRevocationStore_Basic(t *testing.T) {
	store := NewMemoryRevocationStore()
	err := store.Revoke(context.Background(), "sess-1", time.Now().Add(1*time.Hour))
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	revoked, err := store.IsRevoked(context.Background(), "sess-1")
	if err != nil {
		t.Fatalf("IsRevoked failed: %v", err)
	}
	if !revoked {
		t.Fatalf("expected revoked to be true")
	}
	// Expiry
	err = store.Revoke(context.Background(), "sess-2", time.Now().Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("Revoke failed: %v", err)
	}
	revoked, _ = store.IsRevoked(context.Background(), "sess-2")
	if revoked {
		t.Fatalf("expected expired session to not be revoked")
	}
}

func TestJWTStrategy_Revocation(t *testing.T) {
	secret := "test-secret"
	strategy := NewHS256Strategy(secret, 1*time.Hour)
	store := NewMemoryRevocationStore()
	strategy.WithRevocationStore(store)

	sess, err := strategy.Create("sess-1", "user-1")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Validate should succeed
	_, err = strategy.Validate(sess.ID)
	if err != nil {
		t.Fatalf("Validate failed: %v", err)
	}

	// Revoke
	err = strategy.Delete(sess.ID)
	if err != nil {
		t.Fatalf("Delete (revoke) failed: %v", err)
	}

	// Validate should now fail
	_, err = strategy.Validate(sess.ID)
	if err == nil || err.Error() != "session revoked" {
		t.Fatalf("expected session revoked error, got %v", err)
	}
}
