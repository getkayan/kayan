package oauth2

import (
	"context"
	"time"
)

// Token endpoint authentication methods (RFC 8414).
const (
	// AuthMethodClientSecretBasic sends the secret in the Authorization header.
	AuthMethodClientSecretBasic = "client_secret_basic"
	// AuthMethodClientSecretPost sends the secret in the request body.
	AuthMethodClientSecretPost = "client_secret_post"
	// AuthMethodNone is for public clients, which cannot keep a secret.
	// A client using it must use PKCE.
	AuthMethodNone = "none"
)

// Client represents an OAuth2 client application.
type Client struct {
	ID string `json:"id"`

	// SecretHash is the hashed client secret, produced by the [domain.Hasher]
	// the provider was configured with. It is never the secret itself: a
	// database disclosure would otherwise hand over every client credential.
	//
	// Leave it empty for public clients, which must set
	// TokenEndpointAuthMethod to [AuthMethodNone].
	SecretHash string `json:"-"`

	// RedirectURIs is the allowlist this client may redirect to. It is
	// enforced by exact string match — a prefix or wildcard match turns the
	// authorization endpoint into an open redirector.
	RedirectURIs []string `json:"redirect_uris"`

	// GrantTypes limits which grants this client may use.
	GrantTypes []string `json:"grant_types"`

	Scopes  []string `json:"scopes"`
	AppName string   `json:"app_name"`

	// TokenEndpointAuthMethod is how this client authenticates. Defaults to
	// [AuthMethodClientSecretBasic] when empty, so a client is confidential
	// unless it says otherwise.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`

	BackChannelLogoutURI string `json:"back_channel_logout_uri"`

	// PostLogoutRedirectURIs is the allowlist this client may be redirected to
	// after an RP-initiated logout. Like RedirectURIs it is matched exactly:
	// a prefix or wildcard match turns the end-session endpoint into an open
	// redirector on an authentication domain.
	//
	// An empty list denies every redirect, which is the safe reading of "this
	// client registered none".
	PostLogoutRedirectURIs []string `json:"post_logout_redirect_uris"`
}

// AllowsPostLogoutRedirectURI reports whether uri may be redirected to after
// this client ends a session.
//
// The comparison is exact. An empty allowlist denies everything.
func (c *Client) AllowsPostLogoutRedirectURI(uri string) bool {
	for _, allowed := range c.PostLogoutRedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// IsPublic reports whether the client authenticates with no secret.
func (c *Client) IsPublic() bool {
	return c.TokenEndpointAuthMethod == AuthMethodNone
}

// authMethod returns the effective authentication method.
func (c *Client) authMethod() string {
	if c.TokenEndpointAuthMethod == "" {
		return AuthMethodClientSecretBasic
	}
	return c.TokenEndpointAuthMethod
}

// AllowsRedirectURI reports whether uri is registered for this client.
//
// The comparison is exact. Prefix matching would let
// https://good.example.com.attacker.test through, and any form of wildcard
// matching has the same failure mode.
func (c *Client) AllowsRedirectURI(uri string) bool {
	for _, allowed := range c.RedirectURIs {
		if allowed == uri {
			return true
		}
	}
	return false
}

// AllowsGrantType reports whether this client may use the given grant.
//
// A client with no declared grants is unrestricted, which keeps existing
// registrations working; declaring any grant opts into enforcement.
func (c *Client) AllowsGrantType(grant string) bool {
	if len(c.GrantTypes) == 0 {
		return true
	}
	for _, allowed := range c.GrantTypes {
		if allowed == grant {
			return true
		}
	}
	return false
}

// ClientStore defines the interface for managing OAuth2 clients.
type ClientStore interface {
	GetClient(ctx context.Context, id string) (*Client, error)
	CreateClient(ctx context.Context, client *Client) error
	DeleteClient(ctx context.Context, id string) error
}

// AuthCode represents a temporary authorization code.
type AuthCode struct {
	Code                string   `json:"code"`
	ClientID            string   `json:"client_id"`
	IdentityID          string   `json:"identity_id"`
	RedirectURI         string   `json:"redirect_uri"`
	Scopes              []string `json:"scopes"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	// Nonce binds the ID token to this authorization request, so a token
	// captured from one sign-in cannot be replayed into another (OIDC Core
	// section 15.5.2).
	Nonce     string    `json:"nonce,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AuthCodeStore defines the interface for managing authorization codes.
type AuthCodeStore interface {
	SaveAuthCode(ctx context.Context, code *AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
	DeleteAuthCode(ctx context.Context, code string) error
}

// RefreshToken represents a long-lived token used to obtain new access tokens.
type RefreshToken struct {
	Token      string    `json:"token"`
	ClientID   string    `json:"client_id"`
	IdentityID string    `json:"identity_id"`
	Scopes     []string  `json:"scopes"`
	ExpiresAt  time.Time `json:"expires_at"`

	// FamilyID links every token descended from one authorization. Rotation
	// issues a new token in the same family, so presenting a token that was
	// already redeemed can revoke the whole chain.
	FamilyID string `json:"family_id"`

	// UsedAt records when the token was redeemed. A redeemed token is kept
	// rather than deleted: deleting it makes a replay indistinguishable from
	// an unknown token, and the difference is what detects theft.
	UsedAt *time.Time `json:"used_at,omitempty"`
}

// IsUsed reports whether the token has already been redeemed.
func (t *RefreshToken) IsUsed() bool { return t.UsedAt != nil }

// RefreshTokenStore defines the interface for managing refresh tokens.
type RefreshTokenStore interface {
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
}

// RefreshTokenFamilyStore is an optional extension of [RefreshTokenStore] that
// supports refresh token reuse detection (OAuth 2.1, RFC 9700 section 4.14.2).
//
// When a store implements it, redeeming an already-used refresh token revokes
// every token descended from the same authorization — the signal that a token
// was stolen and replayed. Without it, rotation still issues a new token, but
// a replay is only reported as invalid and the thief's own token keeps working.
type RefreshTokenFamilyStore interface {
	RefreshTokenStore

	// MarkRefreshTokenUsed records that a token was redeemed, keeping it
	// resolvable so a later replay can be detected.
	MarkRefreshTokenUsed(ctx context.Context, token string, usedAt time.Time) error

	// RevokeFamily deletes every refresh token sharing familyID.
	RevokeFamily(ctx context.Context, familyID string) error
}
