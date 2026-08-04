package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/getkayan/kayan/core/identity"
	"github.com/golang-jwt/jwt/v5"
)

func TestServerGenerateIDToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	server := NewServer("https://issuer.example.com", privateKey, "kid-1")
	tokenString, err := server.GenerateIDToken("client-1", "user-1", identity.JSON(`{"email":"user@example.com"}`))
	if err != nil {
		t.Fatalf("generate ID token: %v", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected map claims")
	}
	if claims["iss"] != "https://issuer.example.com" {
		t.Fatalf("unexpected issuer: %v", claims["iss"])
	}
	if claims["sub"] != "user-1" {
		t.Fatalf("unexpected subject: %v", claims["sub"])
	}
	if claims["aud"] != "client-1" {
		t.Fatalf("unexpected audience: %v", claims["aud"])
	}
	if token.Header["kid"] != "kid-1" {
		t.Fatalf("unexpected key id: %v", token.Header["kid"])
	}
	if claims["traits"] == nil {
		t.Fatal("expected traits claim")
	}
}

func TestServerGetDiscovery(t *testing.T) {
	server := NewServer("https://issuer.example.com", nil, "kid-1")
	discovery := server.GetDiscovery("https://issuer.example.com")

	if discovery.Issuer != "https://issuer.example.com" {
		t.Fatalf("unexpected issuer: %q", discovery.Issuer)
	}
	if discovery.AuthorizationEndpoint != "https://issuer.example.com/oauth2/auth" {
		t.Fatalf("unexpected authorization endpoint: %q", discovery.AuthorizationEndpoint)
	}
	if discovery.JwksURI != "https://issuer.example.com/oauth2/jwks" {
		t.Fatalf("unexpected JWKS URI: %q", discovery.JwksURI)
	}
	if len(discovery.ScopesSupported) == 0 {
		t.Fatal("expected scopes to be populated")
	}
}

func TestServerGetDiscovery_AllFields(t *testing.T) {
	server := NewServer("https://auth.example.com", nil, "kid-1")
	d := server.GetDiscovery("https://auth.example.com")

	checks := []struct {
		name  string
		value string
	}{
		{"Issuer", d.Issuer},
		{"AuthorizationEndpoint", d.AuthorizationEndpoint},
		{"TokenEndpoint", d.TokenEndpoint},
		{"UserinfoEndpoint", d.UserinfoEndpoint},
		{"JwksURI", d.JwksURI},
		{"EndSessionEndpoint", d.EndSessionEndpoint},
		{"IntrospectionEndpoint", d.IntrospectionEndpoint},
		{"RevocationEndpoint", d.RevocationEndpoint},
	}

	for _, c := range checks {
		if c.value == "" {
			t.Errorf("discovery field %s is empty", c.name)
		}
	}

	if len(d.ResponseTypesSupported) == 0 {
		t.Error("expected ResponseTypesSupported to be populated")
	}
	if len(d.SubjectTypesSupported) == 0 {
		t.Error("expected SubjectTypesSupported to be populated")
	}
	if len(d.IDTokenSigningAlgValuesSupported) == 0 {
		t.Error("expected IDTokenSigningAlgValuesSupported to be populated")
	}
	if len(d.ClaimsSupported) == 0 {
		t.Error("expected ClaimsSupported to be populated")
	}
}

func TestServerGenerateIDToken_ClaimsVerification(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	server := NewServer("https://auth.example.com", privateKey, "kid-2")
	tokenString, err := server.GenerateIDToken("my-client", "user-42", identity.JSON(`{"email":"test@test.com","name":"Test"}`))
	if err != nil {
		t.Fatalf("generate ID token: %v", err)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		return &privateKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("expected map claims")
	}

	// Verify all standard OIDC claims present
	requiredClaims := []string{"iss", "sub", "aud", "exp", "iat"}
	for _, c := range requiredClaims {
		if claims[c] == nil {
			t.Errorf("missing required claim: %s", c)
		}
	}

	if claims["iss"] != "https://auth.example.com" {
		t.Errorf("unexpected iss: %v", claims["iss"])
	}
	if claims["sub"] != "user-42" {
		t.Errorf("unexpected sub: %v", claims["sub"])
	}
	if claims["aud"] != "my-client" {
		t.Errorf("unexpected aud: %v", claims["aud"])
	}

	// exp should be in the future
	exp, ok := claims["exp"].(float64)
	if !ok || exp <= 0 {
		t.Error("exp claim should be a positive number")
	}

	// iat should be recent
	iat, ok := claims["iat"].(float64)
	if !ok || iat <= 0 {
		t.Error("iat claim should be a positive number")
	}

	// kid in header
	if token.Header["kid"] != "kid-2" {
		t.Errorf("unexpected kid: %v", token.Header["kid"])
	}
}
