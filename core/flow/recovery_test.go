package flow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
)

func TestRecoveryManager_Initiate(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	repo.creds["user@example.com:password"] = &identity.Credential{
		IdentityID: "user-1",
		Type:       "password",
		Identifier: "user@example.com",
		Secret:     "hashed",
	}
	tokenStore := &mockTokenStore{tokens: make(map[string]*domain.AuthToken)}
	hasher := NewBcryptHasher(4)

	mgr := NewRecoveryManager(repo, tokenStore, hasher)

	token, err := mgr.Initiate(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if token == nil {
		t.Fatal("expected token, got nil")
	}
	if token.Type != "recovery" {
		t.Fatalf("expected token type 'recovery', got %q", token.Type)
	}
	if token.IdentityID != "user-1" {
		t.Fatalf("expected identity ID 'user-1', got %q", token.IdentityID)
	}
}

func TestRecoveryManager_ResetPassword(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	repo.creds["user@example.com:password"] = &identity.Credential{
		IdentityID: "user-1",
		Type:       "password",
		Identifier: "user@example.com",
		Secret:     "oldhash",
	}
	tokenStore := &mockTokenStore{tokens: make(map[string]*domain.AuthToken)}
	hasher := NewBcryptHasher(4)

	mgr := NewRecoveryManager(repo, tokenStore, hasher)

	token, err := mgr.Initiate(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}

	err = mgr.ResetPassword(context.Background(), token.Token, "newpassword1")
	if err != nil {
		t.Fatalf("reset password: %v", err)
	}

	// Token should be consumed
	if _, ok := tokenStore.tokens[token.Token]; ok {
		t.Fatal("expected token to be deleted after reset")
	}

	// Credential should be updated
	cred := repo.creds["user@example.com:password"]
	if !hasher.Compare("newpassword1", cred.Secret) {
		t.Fatal("expected credential secret to be updated")
	}
}

func TestRecoveryManager_ExpiredToken(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	repo.creds["user@example.com:password"] = &identity.Credential{
		IdentityID: "user-1",
		Type:       "password",
		Identifier: "user@example.com",
		Secret:     "hashed",
	}
	tokenStore := &mockTokenStore{tokens: make(map[string]*domain.AuthToken)}
	hasher := NewBcryptHasher(4)

	mgr := NewRecoveryManager(repo, tokenStore, hasher, WithRecoveryTTL(-1*time.Second))

	token, err := mgr.Initiate(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}

	// Token TTL is 0 so it should be expired immediately
	err = mgr.ResetPassword(context.Background(), token.Token, "newpassword1")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestRecoveryManager_RateLimiting(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	repo.creds["user@example.com:password"] = &identity.Credential{
		IdentityID: "user-1",
		Type:       "password",
		Identifier: "user@example.com",
		Secret:     "hashed",
	}
	tokenStore := &mockTokenStore{tokens: make(map[string]*domain.AuthToken)}
	hasher := NewBcryptHasher(4)
	limiter := NewMemoryRateLimiter()

	mgr := NewRecoveryManager(repo, tokenStore, hasher,
		WithRecoveryRateLimit(limiter, 2, time.Minute),
	)

	// First two calls should succeed
	_, err := mgr.Initiate(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("first initiate: %v", err)
	}
	_, err = mgr.Initiate(context.Background(), "user@example.com")
	if err != nil {
		t.Fatalf("second initiate: %v", err)
	}

	// Third call should be rate limited
	_, err = mgr.Initiate(context.Background(), "user@example.com")
	if !errors.Is(err, ErrRecoveryRateLimited) {
		t.Fatalf("expected ErrRecoveryRateLimited, got %v", err)
	}
}
