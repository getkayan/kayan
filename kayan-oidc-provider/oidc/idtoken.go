package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/getkayan/kayan/core/keys"
	"github.com/golang-jwt/jwt/v5"
)

// ClaimsSource supplies the claims for an identity.
//
// Kayan cannot know where a claim lives in your model — whether "email" is a
// column, a key in a JSON blob, or a lookup against another service — so the
// mapping is yours. Return only the claims the granted scopes permit; the
// result is placed in the ID token as-is.
type ClaimsSource interface {
	Claims(ctx context.Context, identityID string, scopes []string) (map[string]any, error)
}

// ClaimsSourceFunc adapts a function to [ClaimsSource].
type ClaimsSourceFunc func(ctx context.Context, identityID string, scopes []string) (map[string]any, error)

// Claims implements [ClaimsSource].
func (f ClaimsSourceFunc) Claims(ctx context.Context, identityID string, scopes []string) (map[string]any, error) {
	return f(ctx, identityID, scopes)
}

// IDTokenRequest describes an ID token to issue.
type IDTokenRequest struct {
	ClientID   string
	IdentityID string
	Scopes     []string

	// Nonce echoes the authorization request's nonce. The relying party
	// compares it against the value it sent, which is what stops an ID token
	// captured from one sign-in being replayed into another (OIDC Core
	// section 3.1.3.7).
	Nonce string

	// AuthTime is when the user actually authenticated, as opposed to when the
	// token was issued. A relying party asking for max_age needs it.
	AuthTime time.Time

	// TTL overrides the token lifetime. Defaults to [DefaultIDTokenTTL].
	TTL time.Duration
}

// DefaultIDTokenTTL is how long an ID token is valid when no TTL is given.
const DefaultIDTokenTTL = time.Hour

// IssueIDToken mints an ID token for a request.
//
// Claims come from the configured [ClaimsSource], filtered by the granted
// scopes. Reserved claims are set here and cannot be overridden by the source:
// a source that could set "sub" or "aud" would be able to mint a token for
// another subject or audience.
//
// It is preferred over [Server.GenerateIDToken], which emits the whole traits
// blob regardless of scope and carries no nonce.
func (s *Server) IssueIDToken(ctx context.Context, req IDTokenRequest) (string, error) {
	if req.ClientID == "" {
		return "", fmt.Errorf("oidc: client ID is required")
	}
	if req.IdentityID == "" {
		return "", fmt.Errorf("oidc: identity ID is required")
	}

	now := s.now()
	ttl := req.TTL
	if ttl <= 0 {
		ttl = DefaultIDTokenTTL
	}

	claims := jwt.MapClaims{}

	if s.claims != nil {
		supplied, err := s.claims.Claims(ctx, req.IdentityID, req.Scopes)
		if err != nil {
			return "", fmt.Errorf("oidc: resolve claims: %w", err)
		}
		for name, value := range supplied {
			claims[name] = value
		}
	}

	// Reserved claims are written last so a claims source cannot forge them.
	claims["iss"] = s.issuer
	claims["sub"] = req.IdentityID
	claims["aud"] = req.ClientID
	claims["exp"] = now.Add(ttl).Unix()
	claims["iat"] = now.Unix()

	if req.Nonce != "" {
		claims["nonce"] = req.Nonce
	}
	if !req.AuthTime.IsZero() {
		claims["auth_time"] = req.AuthTime.Unix()
	}

	return s.sign(ctx, claims)
}

// sign produces the compact serialization of claims.
func (s *Server) sign(ctx context.Context, claims jwt.Claims) (string, error) {
	// A key provider carries the algorithm with each key, so rotation and
	// non-RSA keys both work.
	if s.keyProvider != nil {
		signer := keys.NewJWTSigner(s.keyProvider)
		return signer.Sign(ctx, claims, nil)
	}

	// Fall back to the single key the server was constructed with.
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if s.keyID != "" {
		token.Header["kid"] = s.keyID
	}
	return token.SignedString(s.signingKey)
}

// now reads the server's clock.
func (s *Server) now() time.Time {
	if s.clock != nil {
		return s.clock.Now()
	}
	return time.Now()
}
