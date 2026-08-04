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
		Secret:       "secret-hash",
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
