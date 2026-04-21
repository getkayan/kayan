package flow

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

func TestPasswordAuth_Default(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}

	reg, login := PasswordAuth(repo, func() any { return &identity.Identity{} }, "email")

	// Register
	traits := identity.JSON(`{"email": "quick@example.com"}`)
	ident, err := reg.Submit(context.Background(), "password", traits, "securepass123")
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	if ident == nil {
		t.Fatal("expected identity, got nil")
	}

	// Login
	result, err := login.Authenticate(context.Background(), "password", "quick@example.com", "securepass123")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected identity, got nil")
	}
}

func TestPasswordAuth_DefaultIdentifierField(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}

	// Empty identifierField should default to "email"
	reg, login := PasswordAuth(repo, func() any { return &identity.Identity{} }, "")

	traits := identity.JSON(`{"email": "default@example.com"}`)
	_, err := reg.Submit(context.Background(), "password", traits, "pass12345")
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}

	_, err = login.Authenticate(context.Background(), "password", "default@example.com", "pass12345")
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
}

func TestPasswordAuth_WithOptions(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}

	var hookCalled bool
	postHook := func(ctx context.Context, ident any) error {
		hookCalled = true
		return nil
	}

	reg, _ := PasswordAuth(repo, func() any { return &identity.Identity{} }, "email",
		WithHasherCost(4),
		WithRegHook(nil, postHook),
	)

	traits := identity.JSON(`{"email": "hooked@example.com"}`)
	_, err := reg.Submit(context.Background(), "password", traits, "pass12345")
	if err != nil {
		t.Fatalf("registration failed: %v", err)
	}
	if !hookCalled {
		t.Fatal("expected post hook to be called")
	}
}
