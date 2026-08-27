package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/getkayan/kayan/kayan-oidc-provider/oauth2"
)

// Errors returned by [Server.UserInfo].
var (
	// ErrInvalidToken is returned when the presented access token is missing,
	// inactive, or does not identify a person. RFC 6750 maps it to a 401 with
	// WWW-Authenticate: Bearer error="invalid_token".
	ErrInvalidToken = errors.New("oidc: invalid access token")

	// ErrInsufficientScope is returned when the token is valid but was not
	// granted the openid scope. RFC 6750 maps it to a 403 with
	// error="insufficient_scope".
	ErrInsufficientScope = errors.New("oidc: token was not granted the openid scope")
)

// TokenIntrospector reports what an access token authorizes.
//
// [oauth2.Provider] satisfies it, so a deployment usually passes the provider
// it already has. It is an interface so a resource server that validates
// tokens some other way -- a shared cache, a remote introspection endpoint --
// can supply that instead.
type TokenIntrospector interface {
	Introspect(ctx context.Context, token string) (*oauth2.IntrospectionResponse, error)
}

// WithTokenIntrospector supplies the token validator [Server.UserInfo] uses.
func WithTokenIntrospector(t TokenIntrospector) ServerOption {
	return func(s *Server) { s.introspector = t }
}

// UserInfo returns the claims for the identity an access token authenticates.
//
// It is the OpenID Connect UserInfo endpoint's logic without the transport:
// the caller reads the bearer token from the Authorization header, hands it
// over, and serializes the result. Most relying parties call it after the
// token exchange, and every certification profile requires it.
//
// The response always carries "sub", and it is the subject the token
// authenticates rather than anything the claims source returned. A source that
// could set it -- through a bug, a misconfigured mapping, or a trait the user
// controls -- would let the response identify somebody else, and a relying
// party keying its account off "sub" would attach the session to the wrong
// person.
//
// Errors are distinguishable so a handler can map them: ErrInvalidToken to
// 401, ErrInsufficientScope to 403, and anything else to 500. An introspection
// failure is not reported as an invalid token, because telling a relying party
// to reauthenticate during a store outage sends it into a loop instead of
// surfacing the fault.
func (s *Server) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if s.introspector == nil {
		return nil, fmt.Errorf("oidc: UserInfo requires a token introspector (WithTokenIntrospector)")
	}
	if s.claims == nil {
		// Answering with only a subject would look to a relying party like a
		// user whose profile happens to be empty, rather than a provider that
		// was never told where claims live.
		return nil, fmt.Errorf("oidc: UserInfo requires a claims source (WithClaimsSource)")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, ErrInvalidToken
	}

	introspection, err := s.introspector.Introspect(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("oidc: introspect access token: %w", err)
	}
	if introspection == nil || !introspection.Active {
		return nil, ErrInvalidToken
	}

	// A token with no subject authenticates an application rather than a
	// person -- the client credentials grant produces one -- so there is no
	// identity to describe.
	if introspection.Sub == "" {
		return nil, ErrInvalidToken
	}

	scopes := strings.Fields(introspection.Scope)
	if !containsScope(scopes, "openid") {
		// A plain OAuth 2.0 token issued for an API must not open the identity
		// endpoint. Without this an application that hands a third party a
		// narrow API token hands over its users' profile data with it.
		return nil, ErrInsufficientScope
	}

	supplied, err := s.claims.Claims(ctx, introspection.Sub, scopes)
	if err != nil {
		return nil, fmt.Errorf("oidc: resolve claims: %w", err)
	}

	response := make(map[string]any, len(supplied)+1)
	for name, value := range supplied {
		response[name] = value
	}
	// Written last so the claims source cannot forge it.
	response["sub"] = introspection.Sub

	return response, nil
}

func containsScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}
