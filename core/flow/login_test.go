package flow

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

func TestLogin(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	regMgr := NewRegistrationManager(repo, factory)
	logMgr := NewLoginManager(repo)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(14), "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	regMgr.RegisterStrategy(pwStrategy)
	logMgr.RegisterStrategy(pwStrategy)

	traits := identity.JSON(`{"email": "test@example.com"}`) // Simplistic identifier
	password := "password123"

	_, err := regMgr.Submit(context.Background(), "password", traits, password)
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// Successful login
	ident, err := logMgr.Authenticate(context.Background(), "password", "test@example.com", password)
	if err != nil {
		t.Fatalf("failed to login: %v", err)
	}

	if ident == nil {
		t.Fatal("expected identity, got nil")
	}

	// Failed login (wrong password)
	_, err = logMgr.Authenticate(context.Background(), "password", string(traits), "wrongpassword")
	if err == nil {
		t.Error("expected error for wrong password, got nil")
	}

	// Failed login (non-existent user)
	_, err = logMgr.Authenticate(context.Background(), "password", "nonexistent@example.com", password)
	if err == nil {
		t.Error("expected error for non-existent user, got nil")
	}
}
