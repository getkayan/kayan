package flow

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

func TestUnification_ImplicitLinking(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	
	linker := NewDefaultLinker(repo, factory)
	regMgr := NewRegistrationManager(repo, factory)
	regMgr.SetLinker(linker)

	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	regMgr.RegisterStrategy(pwStrategy)

	// 1. Initial Registration via Password
	traits := identity.JSON(`{"email": "unify@example.com", "email_verified": true}`)
	password := "pass123"
	ident1, err := regMgr.Submit(context.Background(), "password", traits, password)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// 2. Mock a second registration attempt (e.g. via OIDC) with same VERIFIED email
	// For this test, we'll re-use the "password" method.
	ident2, err := regMgr.Submit(context.Background(), "password", traits, "newpass")
	if err != nil {
		t.Fatalf("second registration (unification) failed: %v", err)
	}

	// 3. Verify they are the SAME identity
	id1 := ident1.(*identity.Identity).ID
	id2 := ident2.(*identity.Identity).ID
	if id1 != id2 {
		t.Errorf("Expected same identity ID, got %v and %v", id1, id2)
	}

	// 4. Verify linking failed if email is NOT verified
	unverifiedTraits := identity.JSON(`{"email": "unverified@example.com", "email_verified": false}`)
	regMgr.Submit(context.Background(), "password", unverifiedTraits, "pass1")
	ident4, _ := regMgr.Submit(context.Background(), "password", unverifiedTraits, "pass2")
	
	if ident1.(*identity.Identity).ID == ident4.(*identity.Identity).ID {
		t.Error("Expected different identities for unverified emails")
	}
}

func TestUnification_ExplicitLinking(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	
	logMgr := NewLoginManager(repo)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	logMgr.RegisterStrategy(pwStrategy)

	// 1. Existing identity
	ident := &identity.Identity{ID: "user-123"}
	repo.identities["user-123"] = ident

	// 2. Link a new password credential explicitly
	err := logMgr.LinkMethod(context.Background(), ident, "password", "new-login", "new-secret")
	if err != nil {
		t.Fatalf("explicit linking failed: %v", err)
	}

	// 3. Verify credential exists
	cred, err := repo.GetCredentialByIdentifier("new-login", "password")
	if err != nil || cred == nil {
		t.Fatal("linked credential not found in repo")
	}
	if cred.IdentityID != "user-123" {
		t.Errorf("expected identity ID user-123, got %s", cred.IdentityID)
	}
}
