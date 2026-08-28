package oidc

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestIDTokenRefusesMaxAgeWithoutAuthTime is the last place the omission is
// catchable.
//
// OIDC Core section 3.1.3.6 requires auth_time whenever the request carried
// max_age. A token minted without it is well formed, verifies, and tells the
// relying party nothing about the thing it asked for -- so the relying party
// has no basis to reject it and accepts a session of unknown age as a fresh
// authentication.
func TestIDTokenRefusesMaxAgeWithoutAuthTime(t *testing.T) {
	server, _ := hashServer(t)

	maxAge := 300
	token, err := server.IssueIDToken(context.Background(), IDTokenRequest{
		ClientID:      "client-1",
		IdentityID:    "user-1",
		Scopes:        []string{"openid"},
		MaxAgeSeconds: &maxAge,
	})
	if err == nil {
		t.Fatal("an ID token was minted for a max_age request with no auth_time")
	}
	if token != "" {
		t.Error("a token was returned alongside the error")
	}
	if !errors.Is(err, ErrMaxAgeNotSatisfied) {
		t.Errorf("error = %v, want ErrMaxAgeNotSatisfied", err)
	}
}

// TestIDTokenRefusesAStaleAuthentication. An auth_time that is present but
// older than max_age is the same failure with evidence attached.
func TestIDTokenRefusesAStaleAuthentication(t *testing.T) {
	server, _ := hashServer(t)

	maxAge := 60
	_, err := server.IssueIDToken(context.Background(), IDTokenRequest{
		ClientID:      "client-1",
		IdentityID:    "user-1",
		Scopes:        []string{"openid"},
		AuthTime:      time.Now().Add(-time.Hour),
		MaxAgeSeconds: &maxAge,
	})
	if !errors.Is(err, ErrMaxAgeNotSatisfied) {
		t.Errorf("error = %v, want ErrMaxAgeNotSatisfied", err)
	}
}

// TestIDTokenCarriesACRandAMR. A relying party that sent acr_values reads acr
// to find out what it actually got -- OIDC makes acr_values a voluntary
// request, so the answer is the only way to tell.
func TestIDTokenCarriesACRandAMR(t *testing.T) {
	server, _ := hashServer(t)

	maxAge := 3600
	authTime := time.Now().Add(-time.Minute).Truncate(time.Second)
	raw, err := server.IssueIDToken(context.Background(), IDTokenRequest{
		ClientID:      "client-1",
		IdentityID:    "user-1",
		Scopes:        []string{"openid"},
		AuthTime:      authTime,
		ACR:           "urn:example:mfa",
		AMR:           []string{"pwd", "otp"},
		MaxAgeSeconds: &maxAge,
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	claims := claimsOf(t, raw)
	if claims["acr"] != "urn:example:mfa" {
		t.Errorf("acr = %v", claims["acr"])
	}
	amr, ok := claims["amr"].([]any)
	if !ok || len(amr) != 2 {
		t.Errorf("amr = %v, want two entries", claims["amr"])
	}
	if got, ok := claims["auth_time"].(float64); !ok || int64(got) != authTime.Unix() {
		t.Errorf("auth_time = %v, want %d", claims["auth_time"], authTime.Unix())
	}
}

// TestIDTokenOmitsACRWhenUnknown. An acr claim invented where nothing is known
// would tell a relying party that a context was reached when nothing recorded
// one.
func TestIDTokenOmitsACRWhenUnknown(t *testing.T) {
	server, _ := hashServer(t)

	raw, err := server.IssueIDToken(context.Background(), IDTokenRequest{
		ClientID:   "client-1",
		IdentityID: "user-1",
		Scopes:     []string{"openid"},
	})
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}

	claims := claimsOf(t, raw)
	if _, present := claims["acr"]; present {
		t.Errorf("acr = %v, want the claim omitted", claims["acr"])
	}
	if _, present := claims["amr"]; present {
		t.Errorf("amr = %v, want the claim omitted", claims["amr"])
	}
}
