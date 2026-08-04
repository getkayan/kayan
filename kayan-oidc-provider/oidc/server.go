// Package oidc provides OpenID Connect (OIDC) server functionality for Kayan IAM.
//
// This package extends the OAuth 2.0 provider with OIDC capabilities including
// ID token generation, discovery metadata, and userinfo endpoints. It enables
// Kayan to act as an OpenID Provider.
//
// # Features
//
//   - ID token generation with RS256 signing
//   - OIDC Discovery (.well-known/openid-configuration)
//   - Standard claims (sub, iss, aud, exp, iat)
//   - Custom traits in ID tokens
//   - Single Logout (SLO) support
//
// # Endpoints
//
//   - /.well-known/openid-configuration: Discovery document
//   - /oauth2/auth: Authorization endpoint
//   - /oauth2/token: Token endpoint
//   - /oidc/userinfo: UserInfo endpoint
//   - /oidc/logout: End session endpoint
//   - /oauth2/jwks: JSON Web Key Set
//
// # Example Usage
//
//	server := oidc.NewServer("https://auth.example.com", privateKey, "key-1")
//
//	// Get discovery document
//	discovery := server.GetDiscovery("https://auth.example.com")
//
//	// Generate ID token
//	idToken, _ := server.GenerateIDToken(clientID, userID, traits)
package oidc

import (
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/getkayan/kayan/core/keys"
	"github.com/golang-jwt/jwt/v5"
)

// Discovery represents the OIDC discovery metadata.
type Discovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint,omitempty"`
	RevocationEndpoint                string   `json:"revocation_endpoint,omitempty"`
	EndSessionEndpoint                string   `json:"end_session_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported"`
}

type Server struct {
	issuer     string
	signingKey any
	keyID      string

	keyProvider             keys.Provider
	claims                  ClaimsSource
	clock                   domain.Clock
	allowPlainCodeChallenge bool
}

// ServerOption configures a [Server].
type ServerOption func(*Server)

// WithServerKeyProvider supplies the signing keys, so discovery can advertise
// the algorithms actually in use and JWKS can publish them.
func WithServerKeyProvider(kp keys.Provider) ServerOption {
	return func(s *Server) { s.keyProvider = kp }
}

// WithClaimsSource supplies the claims placed in ID tokens.
//
// Without one, tokens carry only the reserved claims. Kayan cannot guess where
// "email" or "name" live in your identity model.
func WithClaimsSource(c ClaimsSource) ServerOption {
	return func(s *Server) { s.claims = c }
}

// WithServerClock sets the clock used for token timestamps.
func WithServerClock(c domain.Clock) ServerOption {
	return func(s *Server) { s.clock = c }
}

// WithServerAllowPlainCodeChallenge records that the provider accepts the
// "plain" PKCE method, so discovery advertises it.
//
// It must match the setting on the OAuth 2.0 provider: advertising a method
// that is refused, or omitting one that is accepted, misleads relying parties.
func WithServerAllowPlainCodeChallenge(allow bool) ServerOption {
	return func(s *Server) { s.allowPlainCodeChallenge = allow }
}

func NewServer(issuer string, signingKey any, keyID string, opts ...ServerOption) *Server {
	s := &Server{
		issuer:     issuer,
		signingKey: signingKey,
		keyID:      keyID,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GenerateIDToken generates a signed OIDC ID Token.
// GenerateIDToken generates a signed OIDC ID Token carrying the raw traits.
//
// Deprecated: use [Server.IssueIDToken]. This version emits the entire traits
// blob regardless of which scopes were granted, and carries no nonce, so a
// relying party cannot bind the token to its authorization request.
func (s *Server) GenerateIDToken(clientID string, identityID string, traits identity.JSON) (string, error) {
	claims := jwt.MapClaims{
		"iss":    s.issuer,
		"sub":    identityID,
		"aud":    clientID,
		"exp":    time.Now().Add(1 * time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"traits": traits, // Optional: include traits in the ID token
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID

	return token.SignedString(s.signingKey)
}

// GetDiscovery returns a discovery document with conventional endpoint paths.
//
// Deprecated: use [Server.BuildDiscovery]. This version hardcodes its values,
// so it advertises the "id_token" response type although no implicit flow
// exists, and RS256 regardless of the key in use. It also assumes endpoint
// paths this library does not choose.
func (s *Server) GetDiscovery(baseURL string) Discovery {
	return Discovery{
		Issuer:                           s.issuer,
		AuthorizationEndpoint:            baseURL + "/oauth2/auth",
		TokenEndpoint:                    baseURL + "/oauth2/token",
		UserinfoEndpoint:                 baseURL + "/oidc/userinfo",
		IntrospectionEndpoint:            baseURL + "/oauth2/introspect",
		RevocationEndpoint:               baseURL + "/oauth2/revoke",
		EndSessionEndpoint:               baseURL + "/oidc/logout",
		JwksURI:                          baseURL + "/oauth2/jwks",
		ResponseTypesSupported:           []string{"code"},
		SubjectTypesSupported:            []string{"public"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
		ScopesSupported:                  []string{"openid", "profile", "email"},
		ClaimsSupported:                  []string{"sub", "iss", "aud", "exp", "iat"},
	}
}
