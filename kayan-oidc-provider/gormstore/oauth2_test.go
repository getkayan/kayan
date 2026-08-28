package gormstore

import (
	"context"
	"testing"
	"time"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func setupRepo(t *testing.T) *OAuth2Repository {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	repo := NewOAuth2Repository(db)
	if err := repo.AutoMigrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return repo
}

// --- OAuth2 Operations ---

func TestOAuth2ClientCRUD(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	client := &oauth2.Client{
		ID:           "client-1",
		SecretHash:   "secret-hash",
		RedirectURIs: []string{"https://example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
		Scopes:       []string{"openid", "profile"},
		AppName:      "Test App",
	}

	if err := repo.CreateClient(ctx, client); err != nil {
		t.Fatalf("CreateClient: %v", err)
	}

	got, err := repo.GetClient(ctx, "client-1")
	if err != nil {
		t.Fatalf("GetClient: %v", err)
	}
	if got.AppName != "Test App" {
		t.Fatalf("expected AppName 'Test App', got %q", got.AppName)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(got.Scopes))
	}

	// List
	clients, err := repo.ListClients(ctx)
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("expected 1 client, got %d", len(clients))
	}

	// Delete
	if err := repo.DeleteClient(ctx, "client-1"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	_, err = repo.GetClient(ctx, "client-1")
	if err == nil {
		t.Fatal("expected error after client delete")
	}
}

func TestOAuth2AuthCode(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	code := &oauth2.AuthCode{
		Code:                "code-abc",
		ClientID:            "client-1",
		IdentityID:          "id-1",
		RedirectURI:         "https://example.com/callback",
		Scopes:              []string{"openid"},
		CodeChallenge:       "challenge123",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	if err := repo.SaveAuthCode(ctx, code); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}

	got, err := repo.GetAuthCode(ctx, "code-abc")
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}
	if got.ClientID != "client-1" {
		t.Fatalf("expected ClientID 'client-1', got %q", got.ClientID)
	}
	if got.CodeChallenge != "challenge123" {
		t.Fatalf("expected CodeChallenge 'challenge123', got %q", got.CodeChallenge)
	}

	if err := repo.DeleteAuthCode(ctx, "code-abc"); err != nil {
		t.Fatalf("DeleteAuthCode: %v", err)
	}
	_, err = repo.GetAuthCode(ctx, "code-abc")
	if err == nil {
		t.Fatal("expected error after auth code delete")
	}
}

func TestOAuth2RefreshToken(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	rt := &oauth2.RefreshToken{
		Token:      "rt-xyz",
		ClientID:   "client-1",
		IdentityID: "id-1",
		Scopes:     []string{"openid", "offline_access"},
		ExpiresAt:  time.Now().Add(30 * 24 * time.Hour),
	}

	if err := repo.SaveRefreshToken(ctx, rt); err != nil {
		t.Fatalf("SaveRefreshToken: %v", err)
	}

	got, err := repo.GetRefreshToken(ctx, "rt-xyz")
	if err != nil {
		t.Fatalf("GetRefreshToken: %v", err)
	}
	if len(got.Scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d", len(got.Scopes))
	}

	if err := repo.DeleteRefreshToken(ctx, "rt-xyz"); err != nil {
		t.Fatalf("DeleteRefreshToken: %v", err)
	}
	_, err = repo.GetRefreshToken(ctx, "rt-xyz")
	if err == nil {
		t.Fatal("expected error after refresh token delete")
	}
}

// TestAuthCodeRoundTripsEveryField covers a field that was silently dropped.
//
// gormAuthCode did not map Nonce, so every GORM deployment stored an
// authorization code, read it back with an empty nonce, and issued an ID token
// carrying no nonce claim. That is the binding between a sign-in and the token
// it produces (OIDC Core 15.5.2): without it, a token captured from one
// sign-in can be replayed into another, and a relying party that checks the
// nonce it sent sees a mismatch it cannot explain.
//
// The assertion is over the whole struct rather than the nonce alone. The
// defect was not that somebody mis-typed a field, it was that a field added to
// the core type never reached the adapter -- and a nonce-only test would not
// catch the next one.
func TestAuthCodeRoundTripsEveryField(t *testing.T) {
	repo := setupRepo(t)
	ctx := context.Background()

	want := &oauth2.AuthCode{
		Code:                "code-1",
		ClientID:            "client-1",
		IdentityID:          "user-1",
		RedirectURI:         "https://rp.example.test/callback",
		Scopes:              []string{"openid", "profile"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Nonce:               "n-0S6_WzA2Mj",
		ExpiresAt:           time.Now().Add(10 * time.Minute).UTC().Truncate(time.Second),
	}

	if err := repo.SaveAuthCode(ctx, want); err != nil {
		t.Fatalf("SaveAuthCode: %v", err)
	}
	got, err := repo.GetAuthCode(ctx, "code-1")
	if err != nil {
		t.Fatalf("GetAuthCode: %v", err)
	}

	if got.Nonce != want.Nonce {
		t.Errorf("Nonce = %q, want %q: the ID token this code produces would carry "+
			"no nonce, losing its binding to the sign-in", got.Nonce, want.Nonce)
	}
	if got.Code != want.Code || got.ClientID != want.ClientID || got.IdentityID != want.IdentityID {
		t.Errorf("identity fields did not survive: %+v", got)
	}
	if got.RedirectURI != want.RedirectURI {
		t.Errorf("RedirectURI = %q, want %q", got.RedirectURI, want.RedirectURI)
	}
	if got.CodeChallenge != want.CodeChallenge || got.CodeChallengeMethod != want.CodeChallengeMethod {
		t.Errorf("PKCE fields did not survive: %+v", got)
	}
	if len(got.Scopes) != len(want.Scopes) {
		t.Errorf("Scopes = %v, want %v", got.Scopes, want.Scopes)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
}
