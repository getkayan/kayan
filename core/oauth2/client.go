package oauth2

import (
	"context"
	"time"
)

// Client represents an OAuth2 client application.
type Client struct {
	ID                   string   `json:"id"`
	Secret               string   `json:"-"`
	RedirectURIs         []string `json:"redirect_uris"`
	GrantTypes           []string `json:"grant_types"`
	Scopes               []string `json:"scopes"`
	AppName              string   `json:"app_name"`
	BackChannelLogoutURI string   `json:"back_channel_logout_uri"`
}

// ClientStore defines the interface for managing OAuth2 clients.
type ClientStore interface {
	GetClient(ctx context.Context, id string) (*Client, error)
	CreateClient(ctx context.Context, client *Client) error
	DeleteClient(ctx context.Context, id string) error
}

// AuthCode represents a temporary authorization code.
type AuthCode struct {
	Code                string    `json:"code"`
	ClientID            string    `json:"client_id"`
	IdentityID          string    `json:"identity_id"`
	RedirectURI         string    `json:"redirect_uri"`
	Scopes              []string  `json:"scopes"`
	CodeChallenge       string    `json:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at"`
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
}

// RefreshTokenStore defines the interface for managing refresh tokens.
type RefreshTokenStore interface {
	SaveRefreshToken(ctx context.Context, token *RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*RefreshToken, error)
	DeleteRefreshToken(ctx context.Context, token string) error
}
