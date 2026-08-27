package oidc

import (
	"context"
	"errors"
	"testing"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
)

// stubIntrospector answers with a fixed introspection result.
type stubIntrospector struct {
	response *oauth2.IntrospectionResponse
	err      error
	seen     string
}

func (s *stubIntrospector) Introspect(_ context.Context, token string) (*oauth2.IntrospectionResponse, error) {
	s.seen = token
	if s.err != nil {
		return nil, s.err
	}
	return s.response, nil
}

func activeToken(sub, scope string) *oauth2.IntrospectionResponse {
	return &oauth2.IntrospectionResponse{Active: true, Sub: sub, Scope: scope}
}

func newUserInfoServer(t *testing.T, introspector TokenIntrospector, claims ClaimsSource) *Server {
	t.Helper()
	return NewServer("https://issuer.example.test", nil, "",
		WithClaimsSource(claims),
		WithTokenIntrospector(introspector),
	)
}

// TestUserInfoReturnsClaimsForAValidToken covers the ordinary path. Most
// relying parties call UserInfo after the token exchange, and every OpenID
// certification profile requires it.
func TestUserInfoReturnsClaimsForAValidToken(t *testing.T) {
	introspector := &stubIntrospector{response: activeToken("user-1", "openid profile email")}
	claims := ClaimsSourceFunc(func(_ context.Context, id string, scopes []string) (map[string]any, error) {
		return map[string]any{"email": "alice@example.test", "name": "Alice"}, nil
	})

	server := newUserInfoServer(t, introspector, claims)

	got, err := server.UserInfo(context.Background(), "access-token-1")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if got["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1", got["sub"])
	}
	if got["email"] != "alice@example.test" {
		t.Errorf("email = %v, want alice@example.test", got["email"])
	}
	if introspector.seen != "access-token-1" {
		t.Errorf("introspected %q, want the presented token", introspector.seen)
	}
}

// TestUserInfoRefusesAnInactiveToken is the access check.
//
// UserInfo returns personal data to whoever presents a token. A revoked or
// expired token must not open it, and "active: false" is exactly how
// introspection reports that.
func TestUserInfoRefusesAnInactiveToken(t *testing.T) {
	introspector := &stubIntrospector{response: &oauth2.IntrospectionResponse{Active: false}}
	claims := ClaimsSourceFunc(func(context.Context, string, []string) (map[string]any, error) {
		t.Error("the claims source was consulted for an inactive token")
		return nil, nil
	})

	server := newUserInfoServer(t, introspector, claims)

	if _, err := server.UserInfo(context.Background(), "revoked-token"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("error = %v, want ErrInvalidToken", err)
	}
}

// TestUserInfoRequiresTheOpenIDScope pins the scope check.
//
// A plain OAuth 2.0 access token, issued for an API and never intended to
// carry identity, must not open the identity endpoint. Without this an
// application that hands a third party a narrow API token would be handing
// over its users' profile data too.
func TestUserInfoRequiresTheOpenIDScope(t *testing.T) {
	introspector := &stubIntrospector{response: activeToken("user-1", "read:invoices")}
	claims := ClaimsSourceFunc(func(context.Context, string, []string) (map[string]any, error) {
		t.Error("the claims source was consulted for a token without the openid scope")
		return nil, nil
	})

	server := newUserInfoServer(t, introspector, claims)

	if _, err := server.UserInfo(context.Background(), "api-token"); !errors.Is(err, ErrInsufficientScope) {
		t.Errorf("error = %v, want ErrInsufficientScope", err)
	}
}

// TestUserInfoPassesTheGrantedScopes covers the filtering contract: the claims
// source decides what each scope releases, and it can only do that if it is
// told which scopes were granted.
func TestUserInfoPassesTheGrantedScopes(t *testing.T) {
	introspector := &stubIntrospector{response: activeToken("user-1", "openid email")}

	var seen []string
	claims := ClaimsSourceFunc(func(_ context.Context, _ string, scopes []string) (map[string]any, error) {
		seen = scopes
		return map[string]any{"email": "alice@example.test"}, nil
	})

	server := newUserInfoServer(t, introspector, claims)
	if _, err := server.UserInfo(context.Background(), "token"); err != nil {
		t.Fatalf("UserInfo: %v", err)
	}

	if len(seen) != 2 || seen[0] != "openid" || seen[1] != "email" {
		t.Errorf("scopes = %v, want [openid email]", seen)
	}
}

// TestUserInfoSubCannotBeOverridden is the impersonation test.
//
// The subject is authenticated by the token, not asserted by the claims
// source. A source that could set "sub" -- through a bug, a misconfigured
// mapping, or a trait the user controls -- would let the response identify
// somebody else, and a relying party keying its account off "sub" would
// attach the session to the wrong person.
func TestUserInfoSubCannotBeOverridden(t *testing.T) {
	introspector := &stubIntrospector{response: activeToken("user-1", "openid")}
	claims := ClaimsSourceFunc(func(context.Context, string, []string) (map[string]any, error) {
		return map[string]any{"sub": "administrator", "email": "alice@example.test"}, nil
	})

	server := newUserInfoServer(t, introspector, claims)

	got, err := server.UserInfo(context.Background(), "token")
	if err != nil {
		t.Fatalf("UserInfo: %v", err)
	}
	if got["sub"] != "user-1" {
		t.Errorf("sub = %v, want user-1: the claims source overrode the authenticated subject", got["sub"])
	}
}

// TestUserInfoReportsAClaimsFailure keeps a broken claims source from
// producing a response that looks like a user with no attributes.
func TestUserInfoReportsAClaimsFailure(t *testing.T) {
	introspector := &stubIntrospector{response: activeToken("user-1", "openid")}
	claimsErr := errors.New("directory unavailable")
	claims := ClaimsSourceFunc(func(context.Context, string, []string) (map[string]any, error) {
		return nil, claimsErr
	})

	server := newUserInfoServer(t, introspector, claims)

	if _, err := server.UserInfo(context.Background(), "token"); !errors.Is(err, claimsErr) {
		t.Errorf("error = %v, want the claims failure", err)
	}
}

// TestUserInfoReportsAnIntrospectionFailure keeps a store outage from reading
// as an invalid token, which would send a relying party into a reauthentication
// loop instead of surfacing the fault.
func TestUserInfoReportsAnIntrospectionFailure(t *testing.T) {
	introspectErr := errors.New("token store unavailable")
	claims := ClaimsSourceFunc(func(context.Context, string, []string) (map[string]any, error) {
		t.Error("the claims source was consulted after introspection failed")
		return nil, nil
	})
	server := newUserInfoServer(t, &stubIntrospector{err: introspectErr}, claims)

	_, err := server.UserInfo(context.Background(), "token")
	if !errors.Is(err, introspectErr) {
		t.Errorf("error = %v, want the introspection failure", err)
	}
	if errors.Is(err, ErrInvalidToken) {
		t.Error("an introspection outage was reported as an invalid token")
	}
}

// TestUserInfoRequiresConfiguration keeps a half-configured server from
// answering. Returning just a subject with no claims would look to a relying
// party like a user whose profile is empty.
func TestUserInfoRequiresConfiguration(t *testing.T) {
	claims := ClaimsSourceFunc(func(context.Context, string, []string) (map[string]any, error) {
		return nil, nil
	})

	noIntrospector := NewServer("https://issuer.example.test", nil, "", WithClaimsSource(claims))
	if _, err := noIntrospector.UserInfo(context.Background(), "token"); err == nil {
		t.Error("UserInfo answered with no token introspector configured")
	}

	noClaims := NewServer("https://issuer.example.test", nil, "",
		WithTokenIntrospector(&stubIntrospector{response: activeToken("user-1", "openid")}))
	if _, err := noClaims.UserInfo(context.Background(), "token"); err == nil {
		t.Error("UserInfo answered with no claims source configured")
	}
}

// TestUserInfoRejectsAnEmptyToken covers the shape a handler produces from a
// request with no Authorization header.
func TestUserInfoRejectsAnEmptyToken(t *testing.T) {
	introspector := &stubIntrospector{response: activeToken("user-1", "openid")}
	claims := ClaimsSourceFunc(func(context.Context, string, []string) (map[string]any, error) {
		t.Error("the claims source was consulted for an empty token")
		return nil, nil
	})

	server := newUserInfoServer(t, introspector, claims)
	if _, err := server.UserInfo(context.Background(), ""); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("error = %v, want ErrInvalidToken", err)
	}
}

// TestUserInfoRefusesATokenWithNoSubject covers a client-credentials token,
// which authenticates an application rather than a person and so has no
// identity to describe.
func TestUserInfoRefusesATokenWithNoSubject(t *testing.T) {
	introspector := &stubIntrospector{response: &oauth2.IntrospectionResponse{
		Active: true, Scope: "openid", ClientID: "service-a",
	}}
	claims := ClaimsSourceFunc(func(context.Context, string, []string) (map[string]any, error) {
		t.Error("the claims source was consulted for a token with no subject")
		return nil, nil
	})

	server := newUserInfoServer(t, introspector, claims)
	if _, err := server.UserInfo(context.Background(), "client-token"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("error = %v, want ErrInvalidToken", err)
	}
}

// TestProviderSatisfiesTokenIntrospector is the assumption the design rests
// on: a deployment passes the oauth2.Provider it already has, rather than
// writing an adapter. If the provider's signature drifts, this fails at
// compile time rather than at the first UserInfo call.
func TestProviderSatisfiesTokenIntrospector(t *testing.T) {
	var _ TokenIntrospector = (*oauth2.Provider)(nil)
}
