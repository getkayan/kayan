package oauth2

import (
	"context"
	"time"
)

// Client represents an OAuth2 client application.
type Client struct {
	ID           string   `json:"id" gorm:"primaryKey"`
	Secret       string   `json:"-"`
	RedirectURIs []string `json:"redirect_uris" gorm:"type:text;serializer:json"`
	GrantTypes   []string `json:"grant_types" gorm:"type:text;serializer:json"`
	Scopes       []string `json:"scopes" gorm:"type:text;serializer:json"`
	AppName      string   `json:"app_name"`
}

// ClientStore defines the interface for managing OAuth2 clients.
type ClientStore interface {
	GetClient(ctx context.Context, id string) (*Client, error)
	CreateClient(ctx context.Context, client *Client) error
	DeleteClient(ctx context.Context, id string) error
}

// AuthCode represents a temporary authorization code.
type AuthCode struct {
	Code        string    `json:"code" gorm:"primaryKey"`
	ClientID    string    `json:"client_id"`
	IdentityID  string    `json:"identity_id"`
	RedirectURI string    `json:"redirect_uri"`
	Scopes      []string  `json:"scopes" gorm:"type:text;serializer:json"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// AuthCodeStore defines the interface for managing authorization codes.
type AuthCodeStore interface {
	SaveAuthCode(ctx context.Context, code *AuthCode) error
	GetAuthCode(ctx context.Context, code string) (*AuthCode, error)
	DeleteAuthCode(ctx context.Context, code string) error
}
