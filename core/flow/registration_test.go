package flow

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

type mockRepo struct {
	identities map[string]any
	creds      map[string]*identity.Credential
}

func (m *mockRepo) CreateIdentity(id any) error {
	if fi, ok := id.(FlowIdentity); ok {
		m.identities[fmt.Sprintf("%v", fi.GetID())] = id
	}
	if cs, ok := id.(CredentialSource); ok {
		for _, c := range cs.GetCredentials() {
			m.creds[c.Identifier+":"+c.Type] = &c
		}
	}
	return nil
}

func (m *mockRepo) GetIdentity(factory func() any, id any) (any, error) {
	return m.identities[fmt.Sprintf("%v", id)], nil
}

func (m *mockRepo) FindIdentity(factory func() any, query map[string]any) (any, error) {
	for _, ident := range m.identities {
		match := true
		v := reflect.ValueOf(ident)
		if v.Kind() == reflect.Ptr {
			v = v.Elem()
		}
		for field, value := range query {
			f := v.FieldByName(field)
			if !f.IsValid() || fmt.Sprintf("%v", f.Interface()) != fmt.Sprintf("%v", value) {
				match = false
				break
			}
		}
		if match {
			return ident, nil
		}
	}
	return nil, errors.New("not found")
}

func (m *mockRepo) GetCredentialByIdentifier(identifier string, method string) (*identity.Credential, error) {
	if method == "" {
		// Find any credential with this identifier
		for key, c := range m.creds {
			// key is identifier:method
			if len(key) > len(identifier) && key[:len(identifier)] == identifier && key[len(identifier)] == ':' {
				return c, nil
			}
		}
		return nil, nil // Not found
	}
	return m.creds[identifier+":"+method], nil
}

func (m *mockRepo) UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error {
	// Need to find credential by identity ID and method.
	// Our map is keyed by identifier:method.
	// This makes it hard effectively.
	// Simplified mock: Iterate.
	for _, c := range m.creds {
		if c.IdentityID == identityID && c.Type == method {
			c.Secret = secret
			return nil
		}
	}
	return errors.New("credential not found")
}

func (m *mockRepo) UpdateIdentity(ident any) error {
	if fi, ok := ident.(FlowIdentity); ok {
		m.identities[fmt.Sprintf("%v", fi.GetID())] = ident
		return nil
	}
	return errors.New("invalid identity")
}

func (m *mockRepo) ListIdentities(factory func() any, page, limit int) ([]any, error) {
	result := make([]any, 0, len(m.identities))
	for _, ident := range m.identities {
		result = append(result, ident)
	}
	return result, nil
}

func (m *mockRepo) DeleteIdentity(id any) error {
	key := fmt.Sprintf("%v", id)
	delete(m.identities, key)
	return nil
}

func TestRegistration(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	mgr := NewRegistrationManager(repo, func() any {
		return &identity.Identity{}
	})
	hasher := NewBcryptHasher(14)
	pwStrategy := NewPasswordStrategy(repo, hasher, "email", func() any {
		return &identity.Identity{}
	})
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	mgr.RegisterStrategy(pwStrategy)

	traits := identity.JSON(`{"email": "test@example.com"}`)
	password := "password123"

	identRaw, err := mgr.Submit(context.Background(), "password", traits, password)
	if err != nil {
		t.Fatalf("failed to register: %v", err)
	}
	ident := identRaw.(*identity.Identity)

	if string(ident.GetTraits()) != string(traits) {
		t.Errorf("expected traits %s, got %s", traits, ident.GetTraits())
	}

	if len(ident.GetCredentials()) != 1 {
		t.Errorf("expected 1 credential, got %d", len(ident.GetCredentials()))
	}

	if !hasher.Compare(password, ident.GetCredentials()[0].Secret) {
		t.Error("password hash check failed")
	}
}
