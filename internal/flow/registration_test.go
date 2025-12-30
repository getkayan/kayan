package flow

import (
	"context"
	"testing"

	"github.com/getkayan/kayan/internal/identity"
)

type mockRepo struct {
	identities map[string]*identity.Identity
	creds      map[string]*identity.Credential
}

func (m *mockRepo) CreateIdentity(id *identity.Identity) error {
	m.identities[id.ID.String()] = id
	for _, c := range id.Credentials {
		m.creds[c.Identifier+":"+c.Type] = &c
	}
	return nil
}

func (m *mockRepo) GetIdentity(id string) (*identity.Identity, error) {
	return m.identities[id], nil
}

func (m *mockRepo) GetCredentialByIdentifier(identifier string, method string) (*identity.Credential, error) {
	return m.creds[identifier+":"+method], nil
}

func TestRegistration(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]*identity.Identity),
		creds:      make(map[string]*identity.Credential),
	}
	mgr := NewRegistrationManager(repo)
	hasher := NewBcryptHasher(14)
	mgr.RegisterStrategy(NewPasswordStrategy(repo, hasher))

	traits := identity.JSON(`{"email": "test@example.com"}`)
	password := "password123"

	ident, err := mgr.Submit(context.Background(), "password", traits, password)
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}

	if string(ident.Traits) != string(traits) {
		t.Errorf("expected traits %s, got %s", traits, ident.Traits)
	}

	if len(ident.Credentials) != 1 {
		t.Errorf("expected 1 credential, got %d", len(ident.Credentials))
	}

	if !hasher.Compare(password, ident.Credentials[0].Secret) {
		t.Error("password hash check failed")
	}
}
