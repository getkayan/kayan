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
	"github.com/getkayan/kayan/core/domain"
	"golang.org/x/crypto/bcrypt"
)

type testOAuth2Store struct {
	clients       map[string]*Client
	authCodes     map[string]*AuthCode
	refreshTokens map[string]*RefreshToken
	auditEvents   []*audit.AuditEvent
	auditErr      error
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
	if s.auditErr != nil {
		return s.auditErr
	}
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
	store.clients["client-1"] = testClient(t, "top-secret", "https://app.example.com/callback")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	provider := NewProvider(store, store, store, "https://issuer.example.com", privateKey, "kid-1",
		WithProviderAudit(store, func(context.Context, error) {}))

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
	store.clients["client-1"] = testClient(t, "top-secret", "https://app.example.com/callback")
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

	provider := NewProvider(store, store, store, "https://issuer.example.com", privateKey, "kid-1",
		WithProviderAudit(store, func(context.Context, error) {}))

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
	store.clients["client-1"] = testClient(t, "top-secret", "https://app.example.com/callback")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	provider := NewProvider(store, store, store, "https://issuer.example.com", privateKey, "kid-1",
		WithProviderAudit(store, func(context.Context, error) {}))
	code, err := provider.GenerateAuthCode(ctx, "client-1", "user-1", "https://app.example.com/callback", []string{"openid"}, providerChallenge("expected-verifier"), "S256")
	if err != nil {
		t.Fatalf("generate auth code: %v", err)
	}

	_, err = provider.Exchange(ctx, code, "client-1", "top-secret", "https://app.example.com/callback", "wrong-verifier")
	if !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expected ErrInvalidGrant for a bad verifier, got %v", err)
	}
	// A failed exchange is itself worth recording — repeated PKCE failures are
	// what an interception attempt looks like. What must not appear is a
	// success event.
	for _, event := range store.auditEvents {
		if event.Status == "success" {
			t.Fatalf("a success audit event was recorded for a failed PKCE validation: %+v", event)
		}
	}
}

func providerChallenge(verifier string) string {
	hasher := crypto.SHA256.New()
	hasher.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

func TestProviderAuditFailureIsReported(t *testing.T) {
	want := errors.New("audit unavailable")
	store := newTestOAuth2Store()
	store.auditErr = want
	reported := make(chan error, 1)
	provider := NewProvider(store, store, store, "https://issuer.example.com", nil, "",
		WithProviderAudit(store, func(_ context.Context, err error) { reported <- err }))

	provider.logAudit(context.Background(), "oauth2.test", "client", "user", "success", "")
	select {
	case got := <-reported:
		if !errors.Is(got, want) {
			t.Fatalf("reported error = %v, want %v", got, want)
		}
	default:
		t.Fatal("audit persistence failure was not reported")
	}
}

func TestProviderAuditRequiresErrorHandler(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected missing audit error handler to panic")
		}
	}()
	WithProviderAudit(newTestOAuth2Store(), nil)
}

func TestProviderRevokeAndIntrospect(t *testing.T) {
	ctx := context.Background()
	store := newTestOAuth2Store()
	store.clients["client-1"] = testClient(t, "top-secret", "https://app.example.com/callback")

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	revStore := NewMemoryRevocationStore()
	provider := NewProvider(store, store, store, "https://issuer.example.com", privateKey, "kid-1",
		WithRevocationStore(revStore),
	)

	// Generate a token via auth code exchange
	const verifier = "revoke-flow-verifier"
	code, err := provider.GenerateAuthCode(ctx, "client-1", "user-1", "https://app.example.com/callback", []string{"openid"}, providerChallenge(verifier), "S256")
	if err != nil {
		t.Fatalf("generate auth code: %v", err)
	}
	tokens, err := provider.Exchange(ctx, code, "client-1", "top-secret", "https://app.example.com/callback", verifier)
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

// testClient builds a confidential client whose secret is hashed the way a
// real registration would hash it.
func testClient(t *testing.T, secret string, redirectURIs ...string) *Client {
	t.Helper()

	hash, err := domain.NewBcryptHasher(bcrypt.MinCost).Hash(secret)
	if err != nil {
		t.Fatalf("hash client secret: %v", err)
	}
	return &Client{
		ID:           "client-1",
		SecretHash:   hash,
		RedirectURIs: redirectURIs,
	}
}
