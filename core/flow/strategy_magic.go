package flow

import (
	"context"
	"fmt"
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

type MagicLinkStrategy struct {
	repo       IdentityRepository
	tokenStore domain.TokenStore
	ttl        time.Duration
}

func NewMagicLinkStrategy(repo IdentityRepository, store domain.TokenStore) *MagicLinkStrategy {
	return &MagicLinkStrategy{
		repo:       repo,
		tokenStore: store,
		ttl:        15 * time.Minute,
	}
}

func (s *MagicLinkStrategy) ID() string { return "magic_link" }

// Authenticate verifies the magic link token.
// 'identifier' is the email (for double check, optional) or identity ID?
// 'secret' is the token.
func (s *MagicLinkStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
	// 1. Get Token
	token, err := s.tokenStore.GetToken(ctx, secret)
	if err != nil {
		return nil, fmt.Errorf("magic_link: invalid or expired token")
	}

	// 2. Validate Token Type
	if token.Type != "magic_link" {
		return nil, fmt.Errorf("magic_link: invalid token type")
	}

	// 3. Check Expiry (Store should handle this, but double check)
	if token.ExpiresAt.Before(time.Now()) {
		s.tokenStore.DeleteToken(ctx, secret)
		return nil, fmt.Errorf("magic_link: token expired")
	}

	// 4. Find Identity
	// We use the IdentityID from the token
	ident, err := s.repo.GetIdentity(func() any { return &identity.Identity{} }, token.IdentityID)
	if err != nil {
		return nil, fmt.Errorf("magic_link: identity not found")
	}

	// 5. Consume Token (One-time use)
	s.tokenStore.DeleteToken(ctx, secret)

	return ident, nil
}

// Initiate generates a token and prepares it for sending.
// Returns the token object (to be sent via email by the caller/event system).
func (s *MagicLinkStrategy) Initiate(ctx context.Context, identifier string) (any, error) {
	// 1. Find Identity by Identifier (Email)
	// We use GetCredentialByIdentifier which now searches across all credential types (if method is empty)
	// or specifically "magic_link" if we enforce it.
	// Usually magic link sends to the "email" associated with the account.
	// If the user registered with password (email), we find that credential.
	cred, err := s.repo.GetCredentialByIdentifier(identifier, "")
	if err != nil {
		return nil, fmt.Errorf("magic_link: user not found")
	}

	// 2. Generate Token
	tokenVal := uuid.New().String()
	token := &domain.AuthToken{
		Token:      tokenVal,
		IdentityID: cred.IdentityID,
		Type:       "magic_link",
		ExpiresAt:  time.Now().Add(s.ttl),
	}

	// 3. Save Token
	if err := s.tokenStore.SaveToken(ctx, token); err != nil {
		return nil, err
	}

	return token, nil
}
