package flow

import (
	"context"
	"fmt"
	"testing"

	"github.com/getkayan/kayan/identity"
	"github.com/google/uuid"
)

type mockRepo[T any] struct {
	identities map[string]*identity.Identity[T]
	creds      map[string]*identity.Credential[T]
}

func (m *mockRepo[T]) CreateIdentity(id *identity.Identity[T]) error {
	m.identities[fmt.Sprintf("%v", id.ID)] = id
	for _, c := range id.Credentials {
		m.creds[c.Identifier+":"+c.Type] = &c
	}
	return nil
}

func (m *mockRepo[T]) GetIdentity(id T) (*identity.Identity[T], error) {
	return m.identities[fmt.Sprintf("%v", id)], nil
}

func (m *mockRepo[T]) GetCredentialByIdentifier(identifier string, method string) (*identity.Credential[T], error) {
	return m.creds[identifier+":"+method], nil
}

func TestRegistration(t *testing.T) {
	repo := &mockRepo[uuid.UUID]{
		identities: make(map[string]*identity.Identity[uuid.UUID]),
		creds:      make(map[string]*identity.Credential[uuid.UUID]),
	}
	mgr := NewRegistrationManager[uuid.UUID](repo)
	hasher := NewBcryptHasher(14)
	pwStrategy := NewPasswordStrategy[uuid.UUID](repo, hasher, "email")
	pwStrategy.SetIDGenerator(uuid.New)
	mgr.RegisterStrategy(pwStrategy)

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
