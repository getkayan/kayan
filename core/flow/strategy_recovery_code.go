package flow

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/core/domain"
)

// RecoveryCodeRepository is the storage contract for the recovery_code strategy.
type RecoveryCodeRepository interface {
	// FindIdentityByField looks up an identity by a named field and value.
	FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error)
	// FindUnusedRecoveryCodes returns every unused recovery code record for
	// the identity, or an empty slice when none remain. All of them, not the
	// first: the user may present any code they were given.
	FindUnusedRecoveryCodes(ctx context.Context, identityID any) ([]*RecoveryCodeRecord, error)
	// MarkRecoveryCodeUsed marks the code record as used so it cannot be reused.
	MarkRecoveryCodeUsed(ctx context.Context, identityID any, codeID string) error
}

// RecoveryCodeRecord is a single hashed recovery code stored for an identity.
type RecoveryCodeRecord struct {
	ID   string // unique record ID
	Hash string // bcrypt hash of the plaintext code
}

// RecoveryCodeStrategy is a single-step LoginStrategy for MFA recovery.
// Users present one of their pre-generated recovery codes as the "secret" argument
// to Authenticate. Each code is single-use.
type RecoveryCodeStrategy struct {
	repo            RecoveryCodeRepository
	hasher          domain.Hasher
	factory         func() any
	identifierField string
}

// NewRecoveryCodeStrategy creates a RecoveryCodeStrategy.
//
//	strategy := flow.NewRecoveryCodeStrategy(repo, hasher, func() any { return &User{} }, "Email")
//	loginManager.RegisterStrategy(strategy)
func NewRecoveryCodeStrategy(repo RecoveryCodeRepository, hasher domain.Hasher, factory func() any, identifierField string) *RecoveryCodeStrategy {
	return &RecoveryCodeStrategy{
		repo:            repo,
		hasher:          hasher,
		factory:         factory,
		identifierField: identifierField,
	}
}

func (s *RecoveryCodeStrategy) ID() string { return "recovery_code" }

// Authenticate verifies the recovery code and marks it used on success.
func (s *RecoveryCodeStrategy) Authenticate(ctx context.Context, identifier, code string) (any, error) {
	ident, err := s.repo.FindIdentityByField(ctx, s.identifierField, identifier, s.factory)
	if err != nil {
		return nil, ErrRecoveryCodeInvalid
	}

	fi, ok := ident.(FlowIdentity)
	if !ok {
		return nil, fmt.Errorf("flow: recovery_code: identity does not implement FlowIdentity")
	}

	records, err := s.repo.FindUnusedRecoveryCodes(ctx, fi.GetID())
	if err != nil {
		return nil, fmt.Errorf("flow: recovery_code: read codes: %w", err)
	}
	if len(records) == 0 {
		return nil, ErrNoRecoveryCodesRemaining
	}

	// Against every unused code: the user holds a set and may present any of
	// them. Comparing only one record refused every other valid code, and
	// which one was compared depended on the store's ordering.
	var record *RecoveryCodeRecord
	for _, candidate := range records {
		if candidate != nil && s.hasher.Compare(code, candidate.Hash) {
			record = candidate
			break
		}
	}
	if record == nil {
		return nil, ErrRecoveryCodeInvalid
	}

	if err := s.repo.MarkRecoveryCodeUsed(ctx, fi.GetID(), record.ID); err != nil {
		return nil, ErrRecoveryCodeAlreadyUsed
	}

	return ident, nil
}

// GenerateRecoveryCodes generates n cryptographically random hex codes and their bcrypt hashes.
// Show the plaintext codes to the user once; store only the hashes.
func GenerateRecoveryCodes(hasher domain.Hasher, n int) (plaintexts []string, hashes []string, err error) {
	plaintexts = make([]string, 0, n)
	hashes = make([]string, 0, n)
	for i := 0; i < n; i++ {
		code, err := generateSecureToken(16) // 32 hex chars
		if err != nil {
			return nil, nil, fmt.Errorf("flow: recovery_code: generate: %w", err)
		}
		h, err := hasher.Hash(code)
		if err != nil {
			return nil, nil, fmt.Errorf("flow: recovery_code: hash: %w", err)
		}
		plaintexts = append(plaintexts, code)
		hashes = append(hashes, h)
	}
	return plaintexts, hashes, nil
}
