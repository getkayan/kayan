package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/getkayan/kayan/core/oauth2"
	"github.com/golang-jwt/jwt/v5"
)

// mockClientStore implements oauth2.ClientStore and ClientLister.
type mockClientStore struct {
	clients map[string]*oauth2.Client
}

func (s *mockClientStore) GetClient(_ context.Context, id string) (*oauth2.Client, error) {
	c, ok := s.clients[id]
	if !ok {
		return nil, nil
	}
	return c, nil
}

func (s *mockClientStore) CreateClient(_ context.Context, client *oauth2.Client) error {
	s.clients[client.ID] = client
	return nil
}

func (s *mockClientStore) DeleteClient(_ context.Context, id string) error {
	delete(s.clients, id)
	return nil
}

func (s *mockClientStore) ListClients(_ context.Context) ([]*oauth2.Client, error) {
	result := make([]*oauth2.Client, 0, len(s.clients))
	for _, c := range s.clients {
		result = append(result, c)
	}
	return result, nil
}

func TestBackChannelLogout_NotifyLogout(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	var received bool
	var receivedToken string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = true
		receivedToken = r.FormValue("logout_token")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	store := &mockClientStore{
		clients: map[string]*oauth2.Client{
			"client-1": {
				ID:                   "client-1",
				BackChannelLogoutURI: srv.URL,
			},
			"client-2": {
				ID:                   "client-2",
				BackChannelLogoutURI: "", // no logout URI
			},
		},
	}

	notifier := NewBackChannelLogoutNotifier("https://issuer.example.com", privateKey, "kid-1", store)

	err = notifier.NotifyLogout("session-123", "user-1")
	if err != nil {
		t.Fatalf("NotifyLogout: %v", err)
	}

	if !received {
		t.Fatal("expected backchannel logout request to be received")
	}

	// Parse the logout token and verify claims
	token, err := jwt.Parse(receivedToken, func(t *jwt.Token) (interface{}, error) {
		return &privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse logout token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected MapClaims")
	}
	if claims["iss"] != "https://issuer.example.com" {
		t.Fatalf("expected issuer, got %v", claims["iss"])
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("expected sub user-1, got %v", claims["sub"])
	}
	if claims["sid"] != "session-123" {
		t.Fatalf("expected sid session-123, got %v", claims["sid"])
	}
	events, ok := claims["events"].(map[string]any)
	if !ok {
		t.Fatal("expected events claim to be a map")
	}
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Fatal("expected backchannel-logout event key")
	}
}

func TestBackChannelLogout_NoClientLister(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	// A store that does NOT implement ClientLister
	store := &basicClientStore{}
	notifier := NewBackChannelLogoutNotifier("https://issuer.example.com", privateKey, "kid-1", store)

	// Should be a no-op, not an error
	err = notifier.NotifyLogout("session-123", "user-1")
	if err != nil {
		t.Fatalf("expected no-op, got %v", err)
	}
}

func TestBackChannelLogout_NoClientLister_Strict(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	store := &basicClientStore{}
	notifier := NewBackChannelLogoutNotifier(
		"https://issuer.example.com",
		privateKey,
		"kid-1",
		store,
		WithStrictClientListing(),
	)

	err = notifier.NotifyLogout("session-123", "user-1")
	if !errors.Is(err, ErrClientListingUnavailable) {
		t.Fatalf("expected ErrClientListingUnavailable, got %v", err)
	}
}

// basicClientStore only implements oauth2.ClientStore, not ClientLister.
type basicClientStore struct{}

func (s *basicClientStore) GetClient(_ context.Context, _ string) (*oauth2.Client, error) {
	return nil, nil
}
func (s *basicClientStore) CreateClient(_ context.Context, _ *oauth2.Client) error { return nil }
func (s *basicClientStore) DeleteClient(_ context.Context, _ string) error         { return nil }
