package flow

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/getkayan/kayan/core/identity"
)

func TestUnification_ImplicitLinking(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	oidcStrategy := &stubFederatedStrategy{method: "oidc"}
	linker := NewDefaultLinker(repo, factory, map[string]LoginStrategy{
		"oidc": oidcStrategy,
	})
	regMgr := NewRegistrationManager(repo, factory)
	regMgr.SetLinker(linker)

	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	regMgr.RegisterStrategy(pwStrategy)
	regMgr.RegisterStrategy(oidcStrategy)

	// 1. Initial Registration via Password
	traits := identity.JSON(`{"email": "unify@example.com", "email_verified": true}`)
	password := "pass1234"
	ident1, err := regMgr.Submit(context.Background(), "password", traits, password)
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// 2. A second registration arrives over a federated method carrying the
	//    same verified email. This is what unification is for: the identity
	//    provider vouched for the address, so attaching the new method to the
	//    existing account is safe.
	//
	//    It must not be exercised through "password" — a password submission
	//    proves nothing about who sent it, so that path is refused. See
	//    TestUnification_PasswordDoesNotUnify below.
	ident2, err := regMgr.Submit(context.Background(), "oidc", traits, "id-token")
	if err != nil {
		t.Fatalf("federated unification failed: %v", err)
	}
	if oidcStrategy.attached != 1 {
		t.Errorf("Attach called %d times, want 1 — the method was not linked", oidcStrategy.attached)
	}

	// 3. Verify they are the SAME identity
	id1 := ident1.(*identity.Identity).ID
	id2 := ident2.(*identity.Identity).ID
	if id1 != id2 {
		t.Errorf("Expected same identity ID, got %v and %v", id1, id2)
	}

	// 4. Verify linking failed if email is NOT verified. An unverified address
	//    is an unproven claim, so a second registration must create its own
	//    identity rather than attaching to the first.
	unverifiedTraits := identity.JSON(`{"email": "unverified@example.com", "email_verified": false}`)
	ident3, err := regMgr.Submit(context.Background(), "oidc", unverifiedTraits, "id-token")
	if err != nil {
		t.Fatalf("first unverified registration failed: %v", err)
	}
	ident4, err := regMgr.Submit(context.Background(), "oidc", unverifiedTraits, "id-token")
	if err != nil {
		t.Fatalf("second unverified registration failed: %v", err)
	}

	if ident3.(*identity.Identity).ID == ident4.(*identity.Identity).ID {
		t.Error("Expected different identities for unverified emails")
	}
}

// TestUnification_PasswordDoesNotUnify pins the boundary the previous version
// of TestUnification_ImplicitLinking got wrong: it used "password" as a stand-in
// for a federated method and so asserted the account-takeover behaviour as
// correct. Unification requires a method that proves control of the address.
// Submitting a password proves only that the submitter typed one.
func TestUnification_PasswordDoesNotUnify(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	regMgr := NewRegistrationManager(repo, factory)
	regMgr.SetLinker(NewDefaultLinker(repo, factory))
	regMgr.RegisterStrategy(NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory))

	traits := identity.JSON(`{"email": "unify@example.com", "email_verified": true}`)
	if _, err := regMgr.Submit(context.Background(), "password", traits, "pass1234"); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	if _, err := regMgr.Submit(context.Background(), "password", traits, "attacker"); !errors.Is(err, ErrIdentityAlreadyExists) {
		t.Errorf("error = %v, want ErrIdentityAlreadyExists", err)
	}
}

// stubFederatedStrategy stands in for an OIDC or SAML strategy. It must satisfy
// both RegistrationStrategy (so Submit can look it up) and Attacher (so the
// linker can attach the method to the matched identity).
type stubFederatedStrategy struct {
	method   string
	attached int
}

func (s *stubFederatedStrategy) ID() string { return s.method }

func (s *stubFederatedStrategy) Register(ctx context.Context, traits identity.JSON, secret string) (any, error) {
	return &identity.Identity{ID: uuid.New().String(), Traits: traits}, nil
}

func (s *stubFederatedStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
	return nil, errors.New("stub: Authenticate is not exercised by these tests")
}

func (s *stubFederatedStrategy) Attach(ctx context.Context, ident any, identifier, secret string) error {
	s.attached++
	return nil
}

func TestUnification_ExplicitLinking(t *testing.T) {
	ctx := context.Background()
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	logMgr := NewLoginManager(repo, factory)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	logMgr.RegisterStrategy(pwStrategy)

	// 1. Existing identity
	ident := &identity.Identity{ID: "user-123"}
	repo.identities["user-123"] = ident

	// 2. Link a new password credential explicitly
	err := logMgr.LinkMethod(context.Background(), ident, "password", "new-login", "newsecret1")
	if err != nil {
		t.Fatalf("explicit linking failed: %v", err)
	}

	// 3. Verify credential exists
	cred, err := repo.GetCredentialByIdentifier(ctx, "new-login", "password")
	if err != nil || cred == nil {
		t.Fatal("linked credential not found in repo")
	}
	if cred.IdentityID != "user-123" {
		t.Errorf("expected identity ID user-123, got %s", cred.IdentityID)
	}
}

func TestUnification_LinkerLink(t *testing.T) {
	ctx := context.Background()
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)

	linker := NewDefaultLinker(repo, factory, map[string]LoginStrategy{
		"password": pwStrategy,
	})

	// Create an existing identity
	ident := &identity.Identity{ID: "link-user-1"}
	repo.identities["link-user-1"] = ident

	// Link a password credential via the linker
	err := linker.Link(context.Background(), ident, "password", "linked@example.com", "linkedpass1")
	if err != nil {
		t.Fatalf("Link failed: %v", err)
	}

	// Verify credential was created
	cred, err := repo.GetCredentialByIdentifier(ctx, "linked@example.com", "password")
	if err != nil || cred == nil {
		t.Fatal("linked credential not found")
	}
	if cred.IdentityID != "link-user-1" {
		t.Errorf("expected identity ID link-user-1, got %s", cred.IdentityID)
	}
}

func TestUnification_LinkerLink_UnknownMethod(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	linker := NewDefaultLinker(repo, factory)

	ident := &identity.Identity{ID: "user-1"}
	err := linker.Link(context.Background(), ident, "unknown", "id", "secret12")
	if err == nil {
		t.Error("expected error for unknown method")
	}
}
