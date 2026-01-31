package domain

import (
	"context"
	"time"
)

// AuthToken represents a temporary, expiring token used for flows like
// email verification, password recovery, or magic links.
type AuthToken struct {
	Token      string    `json:"token"`
	IdentityID string    `json:"identity_id"`
	Type       string    `json:"type"` // "recovery", "verification", "magic_link"
	ExpiresAt  time.Time `json:"expires_at"`
}

// TokenStore defines the interface for managing transient authentication tokens.
type TokenStore interface {
	SaveToken(ctx context.Context, token *AuthToken) error
	GetToken(ctx context.Context, token string) (*AuthToken, error)
	DeleteToken(ctx context.Context, token string) error
	DeleteExpiredTokens(ctx context.Context) error
}
