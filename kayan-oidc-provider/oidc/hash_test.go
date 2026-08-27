package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/getkayan/kayan/core/keys"
	"github.com/golang-jwt/jwt/v5"
)

func hashServer(t *testing.T) (*Server, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	provider := keys.NewStaticProvider(&keys.Key{
		KID: "kid-1", Method: jwt.SigningMethodRS256,
		Private: key, Public: &key.PublicKey,
	})
	return NewServer("https://issuer.example.test", nil, "",
		WithServerKeyProvider(provider)), key
}

func claimsOf(t *testing.T, token string) jwt.MapClaims {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatalf("claims are %T", parsed.Claims)
	}
	return claims
}

// wantHash computes the OIDC Core section 3.1.3.6 hash: the left half of the
// digest, base64url-encoded without padding.
func wantHash(t *testing.T, value string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:len(sum)/2])
}

// TestIDTokenCarriesAtHash covers the binding between an ID token and the
// access token issued beside it.
//
// Without at_hash a relying party cannot tell that the two arrived together.
// In flows where they travel separately, an attacker who can substitute one
// gets an ID token describing the victim paired with an access token for their
// own account -- or the reverse. Strict clients and every certification
// profile verify it.
func TestIDTokenCarriesAtHash(t *testing.T) {
	server, _ := hashServer(t)

	token, err := server.IssueIDToken(context.Background(), IDTokenRequest{
		ClientID:    "client-1",
		IdentityID:  "user-1",
		AccessToken: "an-access-token",
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	claims := claimsOf(t, token)
	got, ok := claims["at_hash"].(string)
	if !ok {
		t.Fatal("the ID token carries no at_hash")
	}
	if want := wantHash(t, "an-access-token"); got != want {
		t.Errorf("at_hash = %q, want %q", got, want)
	}
}

// TestIDTokenCarriesCHash covers the same binding for the authorization code,
// which matters in the hybrid flow where a code and an ID token are returned
// together from the authorization endpoint.
func TestIDTokenCarriesCHash(t *testing.T) {
	server, _ := hashServer(t)

	token, err := server.IssueIDToken(context.Background(), IDTokenRequest{
		ClientID:   "client-1",
		IdentityID: "user-1",
		Code:       "an-authorization-code",
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	claims := claimsOf(t, token)
	got, ok := claims["c_hash"].(string)
	if !ok {
		t.Fatal("the ID token carries no c_hash")
	}
	if want := wantHash(t, "an-authorization-code"); got != want {
		t.Errorf("c_hash = %q, want %q", got, want)
	}
}

// TestHashClaimsAreOmittedWhenNotApplicable keeps the token honest. An empty
// at_hash is worse than an absent one: a client that checks for the claim's
// presence would verify a hash of nothing and consider it bound.
func TestHashClaimsAreOmittedWhenNotApplicable(t *testing.T) {
	server, _ := hashServer(t)

	token, err := server.IssueIDToken(context.Background(), IDTokenRequest{
		ClientID:   "client-1",
		IdentityID: "user-1",
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	claims := claimsOf(t, token)
	if _, present := claims["at_hash"]; present {
		t.Error("at_hash is present although no access token was issued")
	}
	if _, present := claims["c_hash"]; present {
		t.Error("c_hash is present although no code was issued")
	}
}

// TestHashClaimsCannotBeForgedByTheClaimsSource covers the same impersonation
// shape as sub. A claims source that could set at_hash would let a token
// claim a binding to an access token it was not issued with.
func TestHashClaimsCannotBeForgedByTheClaimsSource(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	provider := keys.NewStaticProvider(&keys.Key{
		KID: "kid-1", Method: jwt.SigningMethodRS256,
		Private: key, Public: &key.PublicKey,
	})
	server := NewServer("https://issuer.example.test", nil, "",
		WithServerKeyProvider(provider),
		WithClaimsSource(ClaimsSourceFunc(func(context.Context, string, []string) (map[string]any, error) {
			return map[string]any{"at_hash": "forged", "c_hash": "forged"}, nil
		})),
	)

	token, err := server.IssueIDToken(context.Background(), IDTokenRequest{
		ClientID:    "client-1",
		IdentityID:  "user-1",
		AccessToken: "an-access-token",
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	claims := claimsOf(t, token)
	if claims["at_hash"] == "forged" {
		t.Error("the claims source overrode at_hash")
	}
	if _, present := claims["c_hash"]; present {
		t.Error("the claims source injected c_hash for a request with no code")
	}
}
