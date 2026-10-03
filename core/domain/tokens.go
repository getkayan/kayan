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
	// ConsumeToken atomically retrieves and deletes a live token of tokenType.
	// Concurrent callers must not both receive the same token.
	ConsumeToken(ctx context.Context, token, tokenType string) (*AuthToken, error)
	DeleteToken(ctx context.Context, token string) error
	DeleteExpiredTokens(ctx context.Context) error
}

// IdentityTokenRevoker is an optional TokenStore capability: deleting every
// token of one type issued to one identity.
//
// OTPStrategy uses it to keep a single live code per identity and to spend
// that code on a wrong guess, which caps an attacker at one try per code
// issued. A store without it still works, but a wrong guess then costs
// nothing, so brute force is held back only by whatever rate limiting or
// lockout wraps the strategy.
type IdentityTokenRevoker interface {
	DeleteIdentityTokens(ctx context.Context, identityID, tokenType string) error
}
