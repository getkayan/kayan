package saml

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/getkayan/kayan/core/identity"
)

// recordingRepo observes what provisioning actually wrote. The shared
// mockIdentityRepo discards every write and returns nil, so it cannot tell a
// provisioning path that links a credential from one that does not — which is
// why the missing link went unnoticed.
type recordingRepo struct {
	*mockIdentityRepo
	created      []any
	credentials  []*identity.Credential
	byIdentifier map[string]*identity.Credential
}

func newRecordingRepo() *recordingRepo {
	return &recordingRepo{
		mockIdentityRepo: newMockIdentityRepo(),
		byIdentifier:     make(map[string]*identity.Credential),
	}
}

func (r *recordingRepo) CreateIdentity(ctx context.Context, ident any) error {
	r.created = append(r.created, ident)
	return nil
}

func (r *recordingRepo) CreateCredential(ctx context.Context, cred any) error {
	c, ok := cred.(*identity.Credential)
	if !ok {
		return fmt.Errorf("unexpected credential type %T", cred)
	}
	r.credentials = append(r.credentials, c)
	r.byIdentifier[c.Identifier] = c
	return nil
}

func (r *recordingRepo) GetCredentialByIdentifier(ctx context.Context, identifier, method string) (*identity.Credential, error) {
	if c, ok := r.byIdentifier[identifier]; ok {
		return c, nil
	}
	return nil, errors.New("credential not found")
}

func (r *recordingRepo) GetIdentity(ctx context.Context, factory func() any, id any) (any, error) {
	for _, ident := range r.created {
		if fi, ok := ident.(interface{ GetID() any }); ok {
			if fmt.Sprintf("%v", fi.GetID()) == fmt.Sprintf("%v", id) {
				return ident, nil
			}
		}
	}
	return nil, errors.New("identity not found")
}

func newProvisioningSP(t *testing.T, repo *recordingRepo, opts ...SPOption) *ServiceProvider {
	t.Helper()
	return NewServiceProvider(
		Config{EntityID: testSPEntityID, ACSUrl: testACSUrl},
		newMockSessionStore(),
		repo,
		func() any { return &mockUser{ID: "generated-id"} },
		opts...,
	)
}

// TestProvisioningRejectsUnknownNameIDByDefault pins the policy decision.
// Creating an account because someone authenticated elsewhere is a choice, and
// for most deployments the identity provider decides who may sign in, not who
// may exist here. It used to happen implicitly with no way to turn it off.
func TestProvisioningRejectsUnknownNameIDByDefault(t *testing.T) {
	repo := newRecordingRepo()
	sp := newProvisioningSP(t, repo)

	user := &SAMLUser{NameID: "stranger@example.com", IdPID: "idp1", Email: "stranger@example.com"}

	if _, err := sp.reconcileIdentity(context.Background(), user, nil); !errors.Is(err, ErrNoSuchIdentity) {
		t.Errorf("error = %v, want ErrNoSuchIdentity", err)
	}
	if len(repo.created) != 0 {
		t.Errorf("an identity was created for an unknown NameID: %d", len(repo.created))
	}
}

// TestProvisioningIsStableAcrossSignOns covers the defect that made the
// built-in path unusable: it created an identity but never wrote the saml:
// credential that the next sign-on looks up. Every sign-on by the same user
// therefore provisioned another identity — the account someone signed in as
// yesterday was not the one they got today, and the table grew without bound.
func TestProvisioningIsStableAcrossSignOns(t *testing.T) {
	ctx := context.Background()
	repo := newRecordingRepo()
	sp := newProvisioningSP(t, repo, WithAutoProvision())

	user := &SAMLUser{NameID: "ada@example.com", IdPID: "idp1", Email: "ada@example.com"}

	first, err := sp.reconcileIdentity(ctx, user, nil)
	if err != nil {
		t.Fatalf("first sign-on: %v", err)
	}
	if len(repo.credentials) != 1 {
		t.Fatalf("credentials written = %d, want 1 — the next sign-on cannot find this identity", len(repo.credentials))
	}
	if got, want := repo.credentials[0].Identifier, "saml:idp1:ada@example.com"; got != want {
		t.Errorf("credential identifier = %q, want %q", got, want)
	}

	second, err := sp.reconcileIdentity(ctx, user, nil)
	if err != nil {
		t.Fatalf("second sign-on: %v", err)
	}
	if len(repo.created) != 1 {
		t.Errorf("identities created = %d, want 1 — the same user was provisioned twice", len(repo.created))
	}
	if first != second {
		t.Error("the second sign-on returned a different identity than the first")
	}
}

// TestProvisioningEscapesAttributeValues covers a JSON injection. Traits were
// built by formatting identity provider attributes into a JSON string literal
// with fmt.Sprintf, so a value containing a double quote closed the string and
// the rest was parsed as structure — letting an attribute rewrite the trait
// object around it.
//
// Attribute values are not trustworthy input: many directories let a user edit
// their own display name, and the assertion is signed as a whole, so a valid
// signature says nothing about what the fields contain.
func TestProvisioningEscapesAttributeValues(t *testing.T) {
	ctx := context.Background()
	repo := newRecordingRepo()
	sp := newProvisioningSP(t, repo, WithAutoProvision())

	user := &SAMLUser{
		NameID: "mallory@example.com",
		IdPID:  "idp1",
		Email:  "mallory@example.com",
		// Closes the first_name string, injects a role, and swallows the rest.
		FirstName: `Mallory","role":"admin","x":"`,
		LastName:  "Smith",
	}

	ident, err := sp.reconcileIdentity(ctx, user, nil)
	if err != nil {
		t.Fatalf("reconcileIdentity: %v", err)
	}

	traits := ident.(*mockUser).GetTraits()

	var decoded map[string]any
	if err := json.Unmarshal(traits, &decoded); err != nil {
		t.Fatalf("traits are not valid JSON, so the value broke the document: %v\n%s", err, traits)
	}
	if _, injected := decoded["role"]; injected {
		t.Errorf("an attribute value injected a top-level key: %s", traits)
	}
	if got := decoded["first_name"]; got != user.FirstName {
		t.Errorf("first_name = %v, want the literal attribute value %q", got, user.FirstName)
	}
	if got := decoded["last_name"]; got != "Smith" {
		t.Errorf("last_name = %v, want Smith — a later field was swallowed", got)
	}
}
