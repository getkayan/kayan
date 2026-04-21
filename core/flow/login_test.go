package flow

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/getkayan/kayan/core/events"
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
	logMgr := NewLoginManager(repo, factory)
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

func TestLogin_StrategyNotFound(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	logMgr := NewLoginManager(repo, func() any { return &identity.Identity{} })

	_, err := logMgr.Authenticate(context.Background(), "nonexistent", "user", "pass")
	if err == nil {
		t.Error("expected error for unknown strategy")
	}
}

func TestLogin_PreHookFailure(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	hookErr := fmt.Errorf("pre-hook denied")
	logMgr := NewLoginManager(repo, factory, WithLoginPreHook(func(ctx context.Context, ident any) error {
		return hookErr
	}))
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	logMgr.RegisterStrategy(pwStrategy)

	_, err := logMgr.Authenticate(context.Background(), "password", "test@example.com", "password123")
	if err != hookErr {
		t.Errorf("expected pre-hook error, got %v", err)
	}
}

func TestLogin_PostHookSuccess(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }

	regMgr := NewRegistrationManager(repo, factory)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	regMgr.RegisterStrategy(pwStrategy)

	traits := identity.JSON(`{"email": "hook@example.com"}`)
	regMgr.Submit(context.Background(), "password", traits, "password123")

	var postHookCalled bool
	logMgr := NewLoginManager(repo, factory, WithLoginPostHook(func(ctx context.Context, ident any) error {
		postHookCalled = true
		return nil
	}))
	logMgr.RegisterStrategy(pwStrategy)

	_, err := logMgr.Authenticate(context.Background(), "password", "hook@example.com", "password123")
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}
	if !postHookCalled {
		t.Error("expected post-hook to be called")
	}
}

func TestLogin_EmptyIdentifier(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	logMgr := NewLoginManager(repo, factory)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	logMgr.RegisterStrategy(pwStrategy)

	_, err := logMgr.Authenticate(context.Background(), "password", "", "password123")
	if err == nil {
		t.Error("expected error for empty identifier")
	}
}

func TestLoginManager_ConcurrentAuthenticate(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	regMgr := NewRegistrationManager(repo, factory)
	logMgr := NewLoginManager(repo, factory)
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(4), "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	regMgr.RegisterStrategy(pwStrategy)
	logMgr.RegisterStrategy(pwStrategy)

	_, err := regMgr.Submit(context.Background(), "password", identity.JSON(`{"email": "concurrent@example.com"}`), "password123")
	if err != nil {
		t.Fatalf("setup register: %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := logMgr.Authenticate(context.Background(), "password", "concurrent@example.com", "password123")
			if err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent auth failed: %v", err)
	}
}

func TestLoginManager_ConcurrentSetters(t *testing.T) {
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	factory := func() any { return &identity.Identity{} }
	logMgr := NewLoginManager(repo, factory)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(3)
		go func() {
			defer wg.Done()
			logMgr.SetDispatcher(events.NewDispatcher())
		}()
		go func() {
			defer wg.Done()
			logMgr.SetStrategyStore(nil)
		}()
		go func() {
			defer wg.Done()
			logMgr.AddPreHook(func(ctx context.Context, ident any) error { return nil })
		}()
	}
	wg.Wait()
}
