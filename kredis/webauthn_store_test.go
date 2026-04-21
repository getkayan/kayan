package kredis

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/getkayan/kayan/core/flow"
	"github.com/redis/go-redis/v9"
)

func setupTestWebAuthnStore(t *testing.T) (*RedisWebAuthnSessionStore, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisWebAuthnSessionStore(client, "")
	return store, mr
}

func testWebAuthnSession() *flow.WebAuthnSessionData {
	return &flow.WebAuthnSessionData{
		Challenge:        "challenge-abc123",
		UserID:           []byte("user-456"),
		UserVerification: "required",
		ExpiresAt:        time.Now().Add(5 * time.Minute),
	}
}

func TestRedisWebAuthnStore_SaveAndGet(t *testing.T) {
	store, mr := setupTestWebAuthnStore(t)
	defer mr.Close()
	ctx := context.Background()

	data := testWebAuthnSession()
	if err := store.SaveSession(ctx, "sess-1", data); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	got, err := store.GetSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Challenge != data.Challenge {
		t.Fatalf("expected challenge %q, got %q", data.Challenge, got.Challenge)
	}
	if string(got.UserID) != string(data.UserID) {
		t.Fatalf("expected UserID %q, got %q", data.UserID, got.UserID)
	}
	if got.UserVerification != data.UserVerification {
		t.Fatalf("expected UserVerification %q, got %q", data.UserVerification, got.UserVerification)
	}
}

func TestRedisWebAuthnStore_SaveWithCredIDs(t *testing.T) {
	store, mr := setupTestWebAuthnStore(t)
	defer mr.Close()
	ctx := context.Background()

	data := testWebAuthnSession()
	data.AllowedCredIDs = [][]byte{
		[]byte("cred-1"),
		[]byte("cred-2"),
		[]byte("cred-3"),
	}

	if err := store.SaveSession(ctx, "sess-creds", data); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	got, err := store.GetSession(ctx, "sess-creds")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if len(got.AllowedCredIDs) != 3 {
		t.Fatalf("expected 3 allowed cred IDs, got %d", len(got.AllowedCredIDs))
	}
	for i, expected := range data.AllowedCredIDs {
		if string(got.AllowedCredIDs[i]) != string(expected) {
			t.Fatalf("cred ID %d: expected %q, got %q", i, expected, got.AllowedCredIDs[i])
		}
	}
}

func TestRedisWebAuthnStore_Delete(t *testing.T) {
	store, mr := setupTestWebAuthnStore(t)
	defer mr.Close()
	ctx := context.Background()

	data := testWebAuthnSession()
	data.AllowedCredIDs = [][]byte{[]byte("cred-1")}
	store.SaveSession(ctx, "sess-del", data)

	if err := store.DeleteSession(ctx, "sess-del"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}

	_, err := store.GetSession(ctx, "sess-del")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestRedisWebAuthnStore_GetNonExistent(t *testing.T) {
	store, mr := setupTestWebAuthnStore(t)
	defer mr.Close()
	ctx := context.Background()

	_, err := store.GetSession(ctx, "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent session")
	}
}

func TestRedisWebAuthnStore_TTLExpiry(t *testing.T) {
	store, mr := setupTestWebAuthnStore(t)
	defer mr.Close()
	ctx := context.Background()

	data := testWebAuthnSession()
	store.SaveSession(ctx, "sess-ttl", data)

	// Fast-forward past the 5-minute TTL
	mr.FastForward(6 * time.Minute)

	_, err := store.GetSession(ctx, "sess-ttl")
	if err == nil {
		t.Fatal("expected session to be expired")
	}
}

func TestRedisWebAuthnStore_CustomPrefix(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("failed to start miniredis: %v", err)
	}
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	store := NewRedisWebAuthnSessionStore(client, "custom:wa:")
	ctx := context.Background()

	data := testWebAuthnSession()
	store.SaveSession(ctx, "sess-prefix", data)

	keys, err := client.Keys(ctx, "custom:wa:*").Result()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("expected keys with custom prefix")
	}
}

func TestRedisWebAuthnStore_OverwriteSession(t *testing.T) {
	store, mr := setupTestWebAuthnStore(t)
	defer mr.Close()
	ctx := context.Background()

	data1 := testWebAuthnSession()
	data1.Challenge = "challenge-1"
	store.SaveSession(ctx, "sess-ow", data1)

	data2 := testWebAuthnSession()
	data2.Challenge = "challenge-2"
	store.SaveSession(ctx, "sess-ow", data2)

	got, err := store.GetSession(ctx, "sess-ow")
	if err != nil {
		t.Fatalf("GetSession: %v", err)
	}
	if got.Challenge != "challenge-2" {
		t.Fatalf("expected overwritten challenge 'challenge-2', got %q", got.Challenge)
	}
}
