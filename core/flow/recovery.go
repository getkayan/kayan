package flow

import (
	"context"
	"fmt"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/google/uuid"
)

type RecoveryManager struct {
	repo        IdentityRepository // To find user and update credential
	tokenStore  domain.TokenStore
	hasher      domain.Hasher
	auditStore  audit.AuditStore
	ttl         time.Duration
	rateLimiter RateLimiter
	rateLimit   int
	rateWindow  time.Duration
}

// RecoveryOption configures the RecoveryManager.
type RecoveryOption func(*RecoveryManager)

// WithRecoveryRateLimit adds rate limiting to recovery initiation and reset.
func WithRecoveryRateLimit(limiter RateLimiter, limit int, window time.Duration) RecoveryOption {
	return func(m *RecoveryManager) {
		m.rateLimiter = limiter
		m.rateLimit = limit
		m.rateWindow = window
	}
}

// WithRecoveryTTL sets the token time-to-live. Default is 1 hour.
func WithRecoveryTTL(ttl time.Duration) RecoveryOption {
	return func(m *RecoveryManager) { m.ttl = ttl }
}

func NewRecoveryManager(repo IdentityRepository, store domain.TokenStore, hasher domain.Hasher, opts ...RecoveryOption) *RecoveryManager {
	storeAudit, ok := repo.(audit.AuditStore)
	var auditStore audit.AuditStore
	if ok {
		auditStore = storeAudit
	}
	m := &RecoveryManager{
		repo:       repo,
		tokenStore: store,
		hasher:     hasher,
		auditStore: auditStore,
		ttl:        1 * time.Hour,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Initiate generates a recovery token.
func (m *RecoveryManager) Initiate(ctx context.Context, identifier string) (*domain.AuthToken, error) {
	// Rate limit check
	if m.rateLimiter != nil {
		allowed, _, err := m.rateLimiter.Allow(ctx, "recovery:initiate:"+identifier, m.rateLimit, m.rateWindow)
		if err != nil {
			return nil, fmt.Errorf("recovery: rate limiter error: %w", err)
		}
		if !allowed {
			return nil, ErrRecoveryRateLimited
		}
	}

	// 1. Find Credential (password type usually)
	cred, err := m.repo.GetCredentialByIdentifier(identifier, "password")
	if err != nil {
		// Security: Don't leak user existence.
		return nil, fmt.Errorf("recovery: user not found or no password credential")
	}

	// 2. Generate Token
	tokenVal := uuid.New().String()
	token := &domain.AuthToken{
		Token:      tokenVal,
		IdentityID: cred.IdentityID,
		Type:       "recovery",
		ExpiresAt:  time.Now().Add(m.ttl),
	}

	// 3. Save Token
	if err := m.tokenStore.SaveToken(ctx, token); err != nil {
		return nil, err
	}

	// Audit
	if m.auditStore != nil {
		m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
			Type:    "identity.recovery.initiate",
			ActorID: identifier,
			Status:  "success",
		})
	}

	return token, nil
}

// ResetPassword consumes the token and updates the password.
func (m *RecoveryManager) ResetPassword(ctx context.Context, tokenStr string, newPassword string) error {
	// Rate limit check
	if m.rateLimiter != nil {
		allowed, _, err := m.rateLimiter.Allow(ctx, "recovery:reset:"+tokenStr, m.rateLimit, m.rateWindow)
		if err != nil {
			return fmt.Errorf("recovery: rate limiter error: %w", err)
		}
		if !allowed {
			return ErrRecoveryRateLimited
		}
	}

	// 1. Get Token
	token, err := m.tokenStore.GetToken(ctx, tokenStr)
	if err != nil {
		return fmt.Errorf("recovery: invalid or expired token")
	}

	if token.Type != "recovery" {
		return fmt.Errorf("recovery: invalid token type")
	}

	if token.ExpiresAt.Before(time.Now()) {
		m.tokenStore.DeleteToken(ctx, tokenStr)
		return fmt.Errorf("recovery: token expired")
	}

	// 2. Hash New Password
	hashed, err := m.hasher.Hash(newPassword)
	if err != nil {
		return err
	}

	// 3. Update Credential
	updater, ok := m.repo.(interface {
		UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error
	})
	if !ok {
		return fmt.Errorf("recovery: storage does not support credential updates")
	}

	if err := updater.UpdateCredentialSecret(ctx, token.IdentityID, "password", hashed); err != nil {
		return err
	}

	// 4. Consume Token
	m.tokenStore.DeleteToken(ctx, tokenStr)

	// Audit
	if m.auditStore != nil {
		m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
			Type:      "identity.recovery.success",
			SubjectID: token.IdentityID,
			Status:    "success",
		})
	}

	return nil
}
