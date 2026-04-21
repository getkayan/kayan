package kredis

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/getkayan/kayan/core/identity"
	"github.com/redis/go-redis/v9"
)

func setupTestSessionStore(t *testing.T) (*RedisSessionStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisSessionStore(client, WithSessionTTL(10*time.Minute))
	return store, mr
}

func testSession() *identity.Session {
	now := time.Now().Truncate(time.Second)
	return &identity.Session{
		ID:               "sess-123",
		IdentityID:       "user-456",
		RefreshToken:     "rt-abc",
		ExpiresAt:        now.Add(1 * time.Hour),
		RefreshExpiresAt: now.Add(24 * time.Hour),
		IssuedAt:         now,
		Active:           true,
	}
}

func TestRedisSessionStore_CreateAndGet(t *testing.T) {
	store, mr := setupTestSessionStore(t)
	defer mr.Close()

	sess := testSession()
	if err := store.CreateSession(sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := store.GetSession("sess-123")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.ID != sess.ID {
		t.Fatalf("expected ID %q, got %q", sess.ID, got.ID)
	}
	if got.IdentityID != sess.IdentityID {
		t.Fatalf("expected IdentityID %q, got %q", sess.IdentityID, got.IdentityID)
	}
	if !got.Active {
		t.Fatal("expected session to be active")
	}
}

func TestRedisSessionStore_GetByRefreshToken(t *testing.T) {
	store, mr := setupTestSessionStore(t)
	defer mr.Close()

	sess := testSession()
	store.CreateSession(sess)

	got, err := store.GetSessionByRefreshToken("rt-abc")
	if err != nil {
		t.Fatalf("GetSessionByRefreshToken: %v", err)
	}
	if got.ID != "sess-123" {
		t.Fatalf("expected ID 'sess-123', got %q", got.ID)
	}
}

func TestRedisSessionStore_Delete(t *testing.T) {
	store, mr := setupTestSessionStore(t)
	defer mr.Close()

	sess := testSession()
	store.CreateSession(sess)

	if err := store.DeleteSession("sess-123"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	_, err := store.GetSession("sess-123")
	if err == nil {
		t.Fatal("expected error after delete")
	}

	_, err = store.GetSessionByRefreshToken("rt-abc")
	if err == nil {
		t.Fatal("expected error for deleted refresh token")
	}
}

func TestRedisSessionStore_GetNonExistent(t *testing.T) {
	store, mr := setupTestSessionStore(t)
	defer mr.Close()

	_, err := store.GetSession("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestRedisSessionStore_TTLExpiry(t *testing.T) {
	store, mr := setupTestSessionStore(t)
	defer mr.Close()

	sess := testSession()
	store.CreateSession(sess)

	// Fast-forward past the TTL
	mr.FastForward(11 * time.Minute)

	_, err := store.GetSession("sess-123")
	if err == nil {
		t.Fatal("expected session to be expired")
	}
}
