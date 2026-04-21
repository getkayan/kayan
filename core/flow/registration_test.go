package flow

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/getkayan/kayan/core/events"
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

type mockRepo struct {
	mu         sync.RWMutex
	identities map[string]any
	creds      map[string]*identity.Credential
}

func (m *mockRepo) CreateIdentity(id any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.identities[fmt.Sprintf("%v", id)], nil
}

func (m *mockRepo) FindIdentity(factory func() any, query map[string]any) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
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
	m.mu.RLock()
	defer m.mu.RUnlock()
	if method == "" {
		for key, c := range m.creds {
			if len(key) > len(identifier) && key[:len(identifier)] == identifier && key[len(identifier)] == ':' {
				return c, nil
			}
		}
		return nil, nil
	}
	return m.creds[identifier+":"+method], nil
}

func (m *mockRepo) UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.creds {
		if c.IdentityID == identityID && c.Type == method {
			c.Secret = secret
			return nil
		}
	}
	return errors.New("credential not found")
}

func (m *mockRepo) UpdateIdentity(ident any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if fi, ok := ident.(FlowIdentity); ok {
		m.identities[fmt.Sprintf("%v", fi.GetID())] = ident
	}
	if cs, ok := ident.(CredentialSource); ok {
		for _, c := range cs.GetCredentials() {
			m.creds[c.Identifier+":"+c.Type] = &c
		}
	}
	return nil
}

func (m *mockRepo) ListIdentities(factory func() any, page, limit int) ([]any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]any, 0, len(m.identities))
	for _, ident := range m.identities {
		result = append(result, ident)
	}
	return result, nil
}

func (m *mockRepo) DeleteIdentity(factory func() any, id any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := fmt.Sprintf("%v", id)
	delete(m.identities, key)
	return nil
}

func (m *mockRepo) CreateCredential(cred any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := cred.(*identity.Credential); ok {
		m.creds[c.Identifier+":"+c.Type] = c
	}
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

func TestRegistration_StrategyNotFound(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	mgr := NewRegistrationManager(repo, func() any { return &identity.Identity{} })

	_, err := mgr.Submit(context.Background(), "nonexistent", identity.JSON(`{}`), "pass12345")
	if err == nil {
		t.Error("expected error for unknown strategy")
	}
}

func TestRegistration_PreHookFailure(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	hookErr := fmt.Errorf("registration denied by hook")
	mgr := NewRegistrationManager(repo, func() any { return &identity.Identity{} },
		WithRegPreHook(func(ctx context.Context, ident any) error {
			return hookErr
		}),
	)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", func() any { return &identity.Identity{} })
	mgr.RegisterStrategy(pwStrategy)

	_, err := mgr.Submit(context.Background(), "password", identity.JSON(`{"email":"a@b.com"}`), "password123")
	if err != hookErr {
		t.Errorf("expected hook error, got %v", err)
	}
}

func TestRegistration_PostHookSuccess(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}

	var postHookCalled bool
	mgr := NewRegistrationManager(repo, func() any { return &identity.Identity{} },
		WithRegPostHook(func(ctx context.Context, ident any) error {
			postHookCalled = true
			return nil
		}),
	)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", func() any { return &identity.Identity{} })
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	mgr.RegisterStrategy(pwStrategy)

	_, err := mgr.Submit(context.Background(), "password", identity.JSON(`{"email":"post@hook.com"}`), "password123")
	if err != nil {
		t.Fatalf("Submit failed: %v", err)
	}
	if !postHookCalled {
		t.Error("expected post-hook to be called")
	}
}

func TestRegistration_EmptyTraits(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	mgr := NewRegistrationManager(repo, func() any { return &identity.Identity{} })
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", func() any { return &identity.Identity{} })
	mgr.RegisterStrategy(pwStrategy)

	_, err := mgr.Submit(context.Background(), "password", identity.JSON(`{}`), "password123")
	// Empty traits should still work (strategy may or may not accept it)
	// but empty []byte traits should fail
	_, err = mgr.Submit(context.Background(), "password", identity.JSON(nil), "password123")
	if err == nil {
		t.Error("expected error for nil traits")
	}
}

func TestRegistrationManager_ConcurrentSubmit(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	mgr := NewRegistrationManager(repo, factory)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	mgr.RegisterStrategy(pwStrategy)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			email := fmt.Sprintf("user%d@example.com", n)
			traits := identity.JSON(fmt.Sprintf(`{"email": "%s"}`, email))
			_, _ = mgr.Submit(context.Background(), "password", traits, "password123")
		}(i)
	}
	wg.Wait()
}

func TestRegistrationManager_ConcurrentSetters(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	mgr := NewRegistrationManager(repo, factory)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			mgr.SetDispatcher(events.NewDispatcher())
		}()
		go func() {
			defer wg.Done()
			mgr.SetSchema(nil)
		}()
		go func() {
			defer wg.Done()
			mgr.SetLinker(nil)
		}()
	}
	wg.Wait()
}

func TestRegistration_PreventPasswordCapture(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	linker := NewDefaultLinker(repo, factory)
	mgr := NewRegistrationManager(repo, factory,
		WithLinker(linker),
		WithPreventPasswordCapture(),
	)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	mgr.RegisterStrategy(pwStrategy)

	// Register first identity with verified email
	traits := identity.JSON(`{"email": "capture@example.com", "email_verified": true}`)
	_, err := mgr.Submit(context.Background(), "password", traits, "password123")
	if err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Second attempt with same verified email should be blocked
	_, err = mgr.Submit(context.Background(), "password", traits, "newpassword1")
	if !errors.Is(err, ErrIdentityAlreadyExists) {
		t.Errorf("expected ErrIdentityAlreadyExists, got %v", err)
	}
}
