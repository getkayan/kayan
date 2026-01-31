package flow

import (
	"context"
	"fmt"
	"testing"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

type mockTokenStore struct {
	tokens map[string]*domain.AuthToken
}

func (m *mockTokenStore) SaveToken(ctx context.Context, token *domain.AuthToken) error {
	m.tokens[token.Token] = token
	return nil
}

func (m *mockTokenStore) GetToken(ctx context.Context, token string) (*domain.AuthToken, error) {
	if t, ok := m.tokens[token]; ok {
		return t, nil
	}
	return nil, fmt.Errorf("token not found")
}

func (m *mockTokenStore) DeleteToken(ctx context.Context, token string) error {
	delete(m.tokens, token)
	return nil
}

func (m *mockTokenStore) DeleteExpiredTokens(ctx context.Context) error {
	return nil
}

func TestMagicLinkFlow(t *testing.T) {
	// 1. Setup
	repo := &mockRepo{
		identities: make(map[string]any),
		creds:      make(map[string]*identity.Credential),
	}
	tokenStore := &mockTokenStore{
		tokens: make(map[string]*domain.AuthToken),
	}

	factory := func() any { return &identity.Identity{} }
	regMgr := NewRegistrationManager(repo, factory)
	logMgr := NewLoginManager(repo)
	logMgr.SetFactory(factory)

	// Register a password strategy just to create the user easily
	pwStrategy := NewPasswordStrategy(repo, NewBcryptHasher(14), "email", factory)
	pwStrategy.SetIDGenerator(func() any { return uuid.New() })
	regMgr.RegisterStrategy(pwStrategy)

	// Register Magic Link Strategy
	magicStrategy := NewMagicLinkStrategy(repo, tokenStore)
	logMgr.RegisterStrategy(magicStrategy)

	// 2. Register user
	// We register with password, but this creates the "email" credential and identity
	traits := identity.JSON(`{"email": "magic@example.com"}`)
	_, err := regMgr.Submit(context.Background(), "password", traits, "ignored")
	if err != nil {
		t.Fatalf("failed registration: %v", err)
	}

	// 3. Initiate Magic Link Login
	// This should generate a token
	res, err := logMgr.InitiateLogin(context.Background(), "magic_link", "magic@example.com")
	if err != nil {
		t.Fatalf("InitiateLogin failed: %v", err)
	}

	authToken, ok := res.(*domain.AuthToken)
	if !ok {
		t.Fatalf("Expected *domain.AuthToken result, got %T", res)
	}

	if authToken.Token == "" {
		t.Error("Token should not be empty")
	}

	// 4. Authenticate using the token
	// method="magic_link", identifier="magic@example.com", secret=token
	identRaw, err := logMgr.Authenticate(context.Background(), "magic_link", "magic@example.com", authToken.Token)
	if err != nil {
		t.Fatalf("Authenticate failed: %v", err)
	}

	ident := identRaw.(*identity.Identity)
	if ident.ID != authToken.IdentityID {
		t.Error("Authenticated identity ID does not match token identity ID")
	}

	// 5. Verify Token is consumed (deleted)
	_, err = tokenStore.GetToken(context.Background(), authToken.Token)
	if err == nil {
		t.Error("Token should be deleted after use")
	}
}
