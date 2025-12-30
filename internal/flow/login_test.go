package flow

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/internal/identity"
)

func TestLogin(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]*identity.Identity),
		creds:      make(map[string]*identity.Credential),
	}
	regMgr := NewRegistrationManager(repo)
	logMgr := NewLoginManager(repo)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(14))
	regMgr.RegisterStrategy(pwStrategy)
	logMgr.RegisterStrategy(pwStrategy)

	traits := identity.JSON(`test@example.com`) // Simplistic identifier
	password := "password123"

	_, err := regMgr.Submit(context.Background(), "password", traits, password)
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	// Successful login
	ident, err := logMgr.Authenticate(context.Background(), "password", string(traits), password)
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
