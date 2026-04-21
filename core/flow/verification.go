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
	auditStore audit.AuditStore
	ttl        time.Duration
	factory    func() any
}

func NewVerificationManager(repo IdentityRepository, store domain.TokenStore, factory func() any) *VerificationManager {
	storeAudit, ok := repo.(audit.AuditStore)
	var auditStore audit.AuditStore
	if ok {
		auditStore = storeAudit
	}
	if factory == nil {
		factory = func() any { return &identity.Identity{} }
	}
	return &VerificationManager{
		repo:       repo,
		tokenStore: store,
		auditStore: auditStore,
		ttl:        24 * time.Hour,
		factory:    factory,
	}
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
	if m.auditStore != nil {
		m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
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
	token, err := m.tokenStore.GetToken(ctx, tokenStr)
	if err != nil {
		return fmt.Errorf("verification: invalid or expired token")
	}

	if token.Type != "verification" {
		return fmt.Errorf("verification: invalid token type")
	}

	if token.ExpiresAt.Before(time.Now()) {
		m.tokenStore.DeleteToken(ctx, tokenStr)
		return fmt.Errorf("verification: token expired")
	}

	// 2. Get Identity
	identRaw, err := m.repo.GetIdentity(m.factory, token.IdentityID)
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

	if err := m.repo.UpdateIdentity(identRaw); err != nil {
		return err
	}

	// 4. Consume Token
	m.tokenStore.DeleteToken(ctx, tokenStr)

	// Audit
	if m.auditStore != nil {
		m.auditStore.SaveEvent(ctx, &audit.AuditEvent{
			Type:      "identity.verification.success",
			SubjectID: fmt.Sprintf("%v", fi.GetID()),
			Status:    "success",
		})
	}

	return nil
}
