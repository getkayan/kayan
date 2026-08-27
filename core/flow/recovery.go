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
	auditSink   *auditSink
	ttl         time.Duration
	rateLimiter RateLimiter
	rateLimit   int
	rateWindow  time.Duration
	revoker     SessionRevoker
}

// SessionRevoker ends every session belonging to an identity.
//
// Both session strategies implement it. It is declared here rather than taken
// as a concrete type so core/flow keeps no dependency on a session
// implementation, and a caller with their own session layer can supply it.
type SessionRevoker interface {
	RevokeAll(ctx context.Context, identityID any) error
}

// WithRecoverySessionRevoker ends the identity's other sessions when a
// password reset completes.
//
// Without it a reset changes the password and leaves every existing session
// alive, so an attacker holding a stolen session keeps it -- while the victim,
// who has just done the one thing everybody believes ends a compromise,
// believes they are safe.
func WithRecoverySessionRevoker(r SessionRevoker) RecoveryOption {
	return func(m *RecoveryManager) { m.revoker = r }
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

// WithRecoveryAudit explicitly enables audit persistence and error reporting.
func WithRecoveryAudit(store audit.AuditStore, onError AuditErrorHandler) RecoveryOption {
	return func(m *RecoveryManager) { m.auditSink = newAuditSink(store, onError) }
}

func NewRecoveryManager(repo IdentityRepository, store domain.TokenStore, hasher domain.Hasher, opts ...RecoveryOption) *RecoveryManager {
	m := &RecoveryManager{
		repo:       repo,
		tokenStore: store,
		hasher:     hasher,
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
	cred, err := m.repo.GetCredentialByIdentifier(ctx, identifier, "password")
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
	if m.auditSink != nil {
		m.auditSink.save(ctx, &audit.AuditEvent{
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
	token, err := m.tokenStore.ConsumeToken(ctx, tokenStr, "recovery")
	if err != nil {
		return fmt.Errorf("recovery: invalid or expired token")
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

	// 4. End every other session.
	//
	// After the credential is updated, so a revocation failure cannot leave
	// the old password working; and reported rather than swallowed, because a
	// reset that did not end the attacker's session has not done what the
	// person asking for it wanted.
	if m.revoker != nil {
		if err := m.revoker.RevokeAll(ctx, token.IdentityID); err != nil {
			if m.auditSink != nil {
				m.auditSink.save(ctx, &audit.AuditEvent{
					Type:      "identity.recovery.failure",
					SubjectID: token.IdentityID,
					Status:    "failure",
					Message:   "password reset but sessions were not revoked: " + err.Error(),
				})
			}
			return fmt.Errorf("recovery: password updated but existing sessions were not revoked: %w", err)
		}
	}

	// Audit
	if m.auditSink != nil {
		m.auditSink.save(ctx, &audit.AuditEvent{
			Type:      "identity.recovery.success",
			SubjectID: token.IdentityID,
			Status:    "success",
		})
	}

	return nil
}
