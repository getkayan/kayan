package session

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testSigningSecret = "test-signing-secret-not-for-production"

func newRevocableStrategy(t *testing.T) (*JWTStrategy, *MemoryRevocationStore) {
	t.Helper()

	store := NewMemoryRevocationStore()
	strategy := NewHS256Strategy(testSigningSecret, time.Hour).WithRevocationStore(store)
	return strategy, store
}

// TestRefreshChecksRevocation covers refresh-token replay.
//
// Refresh parsed the refresh JWT and minted a fresh session without ever
// consulting the revocation store, while Validate did. So revoking a session
// stopped its access token and left its refresh token working: a stolen
// refresh token kept minting new access tokens until it expired on its own,
// seven days later by default, and logging out did not shorten that.
func TestRefreshChecksRevocation(t *testing.T) {
	strategy, _ := newRevocableStrategy(t)
	ctx := context.Background()

	created, err := strategy.Create(ctx, "session-1", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := strategy.Delete(ctx, created.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	if _, err := strategy.Refresh(ctx, created.RefreshToken); err == nil {
		t.Error("a revoked session's refresh token still minted a new session")
	}
}

// TestRefreshRevokesTheTokenItSpends covers rotation.
//
// A refresh token is single use. Presenting one twice means either a replay or
// a stolen token, and the second attempt must fail rather than silently issue
// a second live session.
func TestRefreshRevokesTheTokenItSpends(t *testing.T) {
	strategy, _ := newRevocableStrategy(t)
	ctx := context.Background()

	created, err := strategy.Create(ctx, "session-1", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := strategy.Refresh(ctx, created.RefreshToken); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if _, err := strategy.Refresh(ctx, created.RefreshToken); err == nil {
		t.Error("the same refresh token was redeemed twice")
	}
}

// TestDeleteWithoutRevocationStoreFails covers a logout that lies.
//
// With no revocation store, Delete returned nil. The caller saw a clean
// logout, the token stayed valid until expiry, and nothing anywhere reported
// that the session had not actually been ended. Both JWT constructors left the
// store nil, so this was the default configuration rather than an edge case.
func TestDeleteWithoutRevocationStoreFails(t *testing.T) {
	strategy := NewHS256Strategy(testSigningSecret, time.Hour)
	ctx := context.Background()

	created, err := strategy.Create(ctx, "session-1", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	err = strategy.Delete(ctx, created.ID)
	if err == nil {
		// If Delete claims success the session must genuinely be unusable.
		if _, verr := strategy.Validate(ctx, created.ID); verr == nil {
			t.Error("Delete reported success but the session still validates")
		}
		return
	}
	if !isNoRevocationStore(err) {
		t.Errorf("error = %v, want one naming the missing revocation store", err)
	}
}

func isNoRevocationStore(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "revocation") || strings.Contains(msg, "revoke")
}

// TestRefreshTokenIsNotAnAccessToken guards a confusion that revocation keyed
// on the token string would hide: the two tokens for one session are different
// strings, so anything that revokes one must be shown to affect the other.
func TestRefreshTokenIsNotAnAccessToken(t *testing.T) {
	strategy, _ := newRevocableStrategy(t)
	ctx := context.Background()

	created, err := strategy.Create(ctx, "session-1", "user-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.ID == created.RefreshToken {
		t.Fatal("access and refresh tokens are the same string")
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(created.RefreshToken, &JWTClaims{})
	if err != nil {
		t.Fatalf("parse refresh token: %v", err)
	}
	claims, ok := parsed.Claims.(*JWTClaims)
	if !ok {
		t.Fatalf("claims are %T", parsed.Claims)
	}
	if claims.SessionID == "" {
		t.Error("the refresh token carries no session id, so it cannot be revoked by session")
	}
	if claims.ExpiresAt == nil || !claims.ExpiresAt.After(time.Now()) {
		t.Error("the refresh token is already expired")
	}
}
