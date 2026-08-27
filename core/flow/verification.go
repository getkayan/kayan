package flow

import (
	"context"
	"fmt"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

type VerificationManager struct {
	repo       IdentityRepository
	tokenStore domain.TokenStore
	auditSink  *auditSink
	ttl        time.Duration
	factory    func() any
}

// VerificationOption configures a VerificationManager.
type VerificationOption func(*VerificationManager)

// WithVerificationAudit explicitly enables audit persistence and error reporting.
func WithVerificationAudit(store audit.AuditStore, onError AuditErrorHandler) VerificationOption {
	return func(m *VerificationManager) { m.auditSink = newAuditSink(store, onError) }
}

func NewVerificationManager(repo IdentityRepository, store domain.TokenStore, factory func() any, opts ...VerificationOption) *VerificationManager {
	if factory == nil {
		factory = func() any { return &identity.Identity{} }
	}
	m := &VerificationManager{
		repo:       repo,
		tokenStore: store,
		ttl:        24 * time.Hour,
		factory:    factory,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Initiate generates a verification token.
func (m *VerificationManager) Initiate(ctx context.Context, ident any) (*domain.AuthToken, error) {
	fi, ok := ident.(FlowIdentity)
	if !ok {
		return nil, fmt.Errorf("verification: identity must implement FlowIdentity")
	}

	vi, ok := ident.(VerificationIdentity)
	if !ok {
		return nil, fmt.Errorf("verification: identity does not support verification state")
	}

	if vi.IsVerified() {
		return nil, fmt.Errorf("verification: already verified")
	}

	// 2. Generate Token
	tokenVal := uuid.New().String()
	token := &domain.AuthToken{
		Token:      tokenVal,
		IdentityID: fmt.Sprintf("%v", fi.GetID()),
		Type:       "verification",
		ExpiresAt:  time.Now().Add(m.ttl),
	}

	// 3. Save Token
	if err := m.tokenStore.SaveToken(ctx, token); err != nil {
		return nil, err
	}

	// Audit
	if m.auditSink != nil {
		m.auditSink.save(ctx, &audit.AuditEvent{
			Type:      "identity.verification.initiate",
			SubjectID: fmt.Sprintf("%v", fi.GetID()),
			Status:    "success",
		})
	}

	return token, nil
}

// Verify consumes the token and marks identity as verified.
func (m *VerificationManager) Verify(ctx context.Context, tokenStr string) error {
	// 1. Get Token
	token, err := m.tokenStore.ConsumeToken(ctx, tokenStr, "verification")
	if err != nil {
		return fmt.Errorf("verification: invalid or expired token")
	}

	// 2. Get Identity
	identRaw, err := m.repo.GetIdentity(ctx, m.factory, token.IdentityID)
	if err != nil {
		return fmt.Errorf("verification: identity not found")
	}

	fi, ok := identRaw.(FlowIdentity)
	if !ok {
		return fmt.Errorf("verification: identity must implement FlowIdentity")
	}

	vi, ok := identRaw.(VerificationIdentity)
	if !ok {
		return fmt.Errorf("verification: identity does not support verification state")
	}

	// 3. Update Status
	now := time.Now()
	vi.MarkVerified(now)

	if err := m.repo.UpdateIdentity(ctx, identRaw); err != nil {
		return err
	}

	// Audit
	if m.auditSink != nil {
		m.auditSink.save(ctx, &audit.AuditEvent{
			Type:      "identity.verification.success",
			SubjectID: fmt.Sprintf("%v", fi.GetID()),
			Status:    "success",
		})
	}

	return nil
}
