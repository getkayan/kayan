package oauth2

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/audit"
)

type testOAuth2Store struct {
	clients       map[string]*Client
	authCodes     map[string]*AuthCode
	refreshTokens map[string]*RefreshToken
	auditEvents   []*audit.AuditEvent
}

func newTestOAuth2Store() *testOAuth2Store {
	return &testOAuth2Store{
		clients:       map[string]*Client{},
		authCodes:     map[string]*AuthCode{},
		refreshTokens: map[string]*RefreshToken{},
	}
}

func (s *testOAuth2Store) GetClient(_ context.Context, id string) (*Client, error) {
	client, ok := s.clients[id]
	if !ok {
		return nil, errors.New("client not found")
	}
	return client, nil
}

func (s *testOAuth2Store) CreateClient(_ context.Context, client *Client) error {
	s.clients[client.ID] = client
	return nil
}

func (s *testOAuth2Store) DeleteClient(_ context.Context, id string) error {
	delete(s.clients, id)
	return nil
}

func (s *testOAuth2Store) SaveAuthCode(_ context.Context, code *AuthCode) error {
	s.authCodes[code.Code] = code
	return nil
}

func (s *testOAuth2Store) GetAuthCode(_ context.Context, code string) (*AuthCode, error) {
	authCode, ok := s.authCodes[code]
	if !ok {
		return nil, errors.New("code not found")
	}
	return authCode, nil
}

func (s *testOAuth2Store) DeleteAuthCode(_ context.Context, code string) error {
	delete(s.authCodes, code)
	return nil
}

func (s *testOAuth2Store) SaveRefreshToken(_ context.Context, token *RefreshToken) error {
	s.refreshTokens[token.Token] = token
	return nil
}

func (s *testOAuth2Store) GetRefreshToken(_ context.Context, token string) (*RefreshToken, error) {
	refreshToken, ok := s.refreshTokens[token]
	if !ok {
		return nil, errors.New("refresh token not found")
	}
	return refreshToken, nil
}

func (s *testOAuth2Store) DeleteRefreshToken(_ context.Context, token string) error {
	delete(s.refreshTokens, token)
	return nil
}

func (s *testOAuth2Store) SaveEvent(_ context.Context, event *audit.AuditEvent) error {
	s.auditEvents = append(s.auditEvents, event)
	return nil
}

func (s *testOAuth2Store) Query(context.Context, audit.Filter) ([]audit.AuditEvent, error) {
	return nil, nil
}

func (s *testOAuth2Store) Count(context.Context, audit.Filter) (int64, error) {
	return 0, nil
}

func (s *testOAuth2Store) Export(context.Context, audit.Filter, audit.ExportFormat) (io.Reader, error) {
	return strings.NewReader(""), nil
}

func (s *testOAuth2Store) Purge(context.Context, time.Time) (int64, error) {
	return 0, nil
}

func TestProviderExchangeWithPKCEAndIntrospection(t *testing.T) {
	ctx := context.Background()
	store := newTestOAuth2Store()
	store.clients["client-1"] = &Client{ID: "client-1", Secret: "top-secret"}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	provider := NewProvider(store, store, store, "https://issuer.example.com", privateKey, "kid-1")

	verifier := "verifier-value"
	code, err := provider.GenerateAuthCode(ctx, "client-1", "user-1", "https://app.example.com/callback", []string{"openid", "profile"}, providerChallenge(verifier), "S256")
	if err != nil {
		t.Fatalf("generate auth code: %v", err)
	}

	tokens, err := provider.Exchange(ctx, code, "client-1", "top-secret", "https://app.example.com/callback", verifier)
	if err != nil {
		t.Fatalf("exchange auth code: %v", err)
	}

	if tokens.AccessToken == "" {
		t.Fatal("expected access token to be set")
	}
	if tokens.RefreshToken == "" {
		t.Fatal("expected refresh token to be set")
	}
	if tokens.Sub != "user-1" {
		t.Fatalf("expected subject user-1, got %q", tokens.Sub)
	}
	if _, ok := store.authCodes[code]; ok {
		t.Fatal("expected auth code to be deleted after exchange")
	}

	introspection, err := provider.Introspect(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("introspect token: %v", err)
	}
	if !introspection.Active {
		t.Fatal("expected token to be active")
	}
	if introspection.ClientID != "client-1" {
		t.Fatalf("expected client-1, got %q", introspection.ClientID)
	}
	if introspection.Sub != "user-1" {
		t.Fatalf("expected user-1, got %q", introspection.Sub)
	}
	if introspection.Scope != "openid profile" {
		t.Fatalf("expected scopes to round-trip, got %q", introspection.Scope)
	}

	if len(store.auditEvents) == 0 {
		t.Fatal("expected audit events to be recorded")
	}
	last := store.auditEvents[len(store.auditEvents)-1]
	if last.Type != "oauth2.exchange.success" {
		t.Fatalf("expected success audit event, got %q", last.Type)
	}
}

func TestProviderRefreshRotatesRefreshToken(t *testing.T) {
	ctx := context.Background()
	store := newTestOAuth2Store()
	store.clients["client-1"] = &Client{ID: "client-1", Secret: "top-secret"}
	store.refreshTokens["refresh-old"] = &RefreshToken{
		Token:      "refresh-old",
		ClientID:   "client-1",
		IdentityID: "user-1",
		Scopes:     []string{"openid"},
		ExpiresAt:  time.Now().Add(time.Hour),
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	provider := NewProvider(store, store, store, "https://issuer.example.com", privateKey, "kid-1")

	tokens, err := provider.Refresh(ctx, "refresh-old", "client-1", "top-secret")
	if err != nil {
		t.Fatalf("refresh token: %v", err)
	}

	if tokens.RefreshToken == "" || tokens.RefreshToken == "refresh-old" {
		t.Fatalf("expected rotated refresh token, got %q", tokens.RefreshToken)
	}
	if _, ok := store.refreshTokens["refresh-old"]; ok {
		t.Fatal("expected old refresh token to be deleted")
	}
	if _, ok := store.refreshTokens[tokens.RefreshToken]; !ok {
		t.Fatal("expected new refresh token to be saved")
	}
}

func TestProviderExchangeRejectsInvalidVerifier(t *testing.T) {
	ctx := context.Background()
	store := newTestOAuth2Store()
	store.clients["client-1"] = &Client{ID: "client-1", Secret: "top-secret"}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	provider := NewProvider(store, store, store, "https://issuer.example.com", privateKey, "kid-1")
	code, err := provider.GenerateAuthCode(ctx, "client-1", "user-1", "https://app.example.com/callback", []string{"openid"}, providerChallenge("expected-verifier"), "S256")
	if err != nil {
		t.Fatalf("generate auth code: %v", err)
	}

	_, err = provider.Exchange(ctx, code, "client-1", "top-secret", "https://app.example.com/callback", "wrong-verifier")
	if err == nil || err.Error() != "invalid code verifier" {
		t.Fatalf("expected invalid code verifier error, got %v", err)
	}
	if len(store.auditEvents) != 0 {
		t.Fatal("expected no audit success event on failed PKCE validation")
	}
}

func providerChallenge(verifier string) string {
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

func TestProviderRevokeAndIntrospect(t *testing.T) {
	ctx := context.Background()
	store := newTestOAuth2Store()
	store.clients["client-1"] = &Client{ID: "client-1", Secret: "top-secret"}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	revStore := NewMemoryRevocationStore()
	provider := NewProvider(store, store, store, "https://issuer.example.com", privateKey, "kid-1",
		WithRevocationStore(revStore),
	)

	// Generate a token via auth code exchange
	code, err := provider.GenerateAuthCode(ctx, "client-1", "user-1", "https://app.example.com/callback", []string{"openid"}, "", "")
	if err != nil {
		t.Fatalf("generate auth code: %v", err)
	}
	tokens, err := provider.Exchange(ctx, code, "client-1", "top-secret", "https://app.example.com/callback", "")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}

	// Token should be active
	resp, err := provider.Introspect(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("introspect: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected token to be active before revocation")
	}

	// Revoke
	if err := provider.Revoke(ctx, tokens.AccessToken); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Token should now be inactive
	resp, err = provider.Introspect(ctx, tokens.AccessToken)
	if err != nil {
		t.Fatalf("introspect after revoke: %v", err)
	}
	if resp.Active {
		t.Fatal("expected token to be inactive after revocation")
	}
}

func TestProviderRevokeNoStore(t *testing.T) {
	ctx := context.Background()
	store := newTestOAuth2Store()

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	// Provider without revocation store — backward compatible
	provider := NewProvider(store, store, store, "https://issuer.example.com", privateKey, "kid-1")

	// Revoke should no-op
	if err := provider.Revoke(ctx, "some-token"); err != nil {
		t.Fatalf("expected no-op revoke, got %v", err)
	}
}

func TestMemoryRevocationStore_CleanExpired(t *testing.T) {
	store := NewMemoryRevocationStore()
	ctx := context.Background()

	// Add an already-expired entry
	store.RevokeToken(ctx, "expired-jti", time.Now().Add(-1*time.Hour))
	// Add a still-valid entry
	store.RevokeToken(ctx, "valid-jti", time.Now().Add(1*time.Hour))

	store.CleanExpired()

	revoked, _ := store.IsRevoked(ctx, "expired-jti")
	if revoked {
		t.Fatal("expected expired entry to be cleaned")
	}
	revoked, _ = store.IsRevoked(ctx, "valid-jti")
	if !revoked {
		t.Fatal("expected valid entry to still be revoked")
	}
}
