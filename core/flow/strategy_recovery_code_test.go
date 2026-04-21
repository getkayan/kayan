package flow

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

// ---- mock storage ----

type mockRecoveryRepo struct {
	mu         sync.Mutex
	identities map[string]any                   // "field:value" → identity
	codes      map[string][]*RecoveryCodeRecord // identityID → unused codes
	markErr    error
}

func newMockRecoveryRepo() *mockRecoveryRepo {
	return &mockRecoveryRepo{
		identities: make(map[string]any),
		codes:      make(map[string][]*RecoveryCodeRecord),
	}
}

func (r *mockRecoveryRepo) addIdentity(field, value string, ident any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identities[field+":"+value] = ident
}

func (r *mockRecoveryRepo) addCode(identityID, codeID, hash string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.codes[identityID] = append(r.codes[identityID], &RecoveryCodeRecord{ID: codeID, Hash: hash})
}

func (r *mockRecoveryRepo) FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ident, ok := r.identities[field+":"+value]; ok {
		return ident, nil
	}
	return nil, errors.New("not found")
}

func (r *mockRecoveryRepo) FindUnusedRecoveryCode(ctx context.Context, identityID any) (*RecoveryCodeRecord, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := fmt.Sprintf("%v", identityID)
	if codes, ok := r.codes[id]; ok && len(codes) > 0 {
		return codes[0], nil
	}
	return nil, ErrNoRecoveryCodesRemaining
}

func (r *mockRecoveryRepo) MarkRecoveryCodeUsed(ctx context.Context, identityID any, codeID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.markErr != nil {
		return r.markErr
	}
	id := fmt.Sprintf("%v", identityID)
	codes := r.codes[id]
	for i, c := range codes {
		if c.ID == codeID {
			r.codes[id] = append(codes[:i], codes[i+1:]...)
			return nil
		}
	}
	return errors.New("code not found")
}

// ---- tests ----

func TestRecoveryCodeStrategy_ID(t *testing.T) {
	s := NewRecoveryCodeStrategy(nil, nil, nil, "")
	if s.ID() != "recovery_code" {
		t.Errorf("ID() = %q, want %q", s.ID(), "recovery_code")
	}
}

func TestRecoveryCodeStrategy_Authenticate(t *testing.T) {
	hasher := NewBcryptHasher(4) // low cost for tests
	const validCode = "aabbccddeeff00112233445566778899"

	tests := []struct {
		name       string
		identifier string
		code       string
		setupRepo  func(*mockRecoveryRepo, *identity.Identity)
		wantErr    error
	}{
		{
			name:       "valid code succeeds",
			identifier: "user@example.com",
			code:       validCode,
		},
		{
			name:       "wrong code",
			identifier: "user@example.com",
			code:       "wrongcode",
			wantErr:    ErrRecoveryCodeInvalid,
		},
		{
			name:       "identity not found",
			identifier: "ghost@example.com",
			code:       validCode,
			wantErr:    ErrRecoveryCodeInvalid,
		},
		{
			name:       "no codes remaining",
			identifier: "user@example.com",
			code:       validCode,
			setupRepo: func(r *mockRecoveryRepo, u *identity.Identity) {
				// Remove all codes
				delete(r.codes, u.ID)
			},
			wantErr: ErrNoRecoveryCodesRemaining,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockRecoveryRepo()
			ident := &identity.Identity{ID: uuid.NewString()}
			repo.addIdentity("Email", "user@example.com", ident)

			hash, _ := hasher.Hash(validCode)
			repo.addCode(ident.ID, "code-1", hash)

			if tt.setupRepo != nil {
				tt.setupRepo(repo, ident)
			}

			s := NewRecoveryCodeStrategy(repo, hasher, func() any { return &identity.Identity{} }, "Email")
			got, err := s.Authenticate(context.Background(), tt.identifier, tt.code)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got == nil {
				t.Error("expected identity, got nil")
			}
		})
	}
}

func TestRecoveryCodeStrategy_SingleUse(t *testing.T) {
	hasher := NewBcryptHasher(4)
	const code = "aabbccddeeff00112233445566778899"

	repo := newMockRecoveryRepo()
	ident := &identity.Identity{ID: uuid.NewString()}
	repo.addIdentity("Email", "user@example.com", ident)

	hash, _ := hasher.Hash(code)
	repo.addCode(ident.ID, "code-1", hash)

	s := NewRecoveryCodeStrategy(repo, hasher, func() any { return &identity.Identity{} }, "Email")

	// First use: success.
	if _, err := s.Authenticate(context.Background(), "user@example.com", code); err != nil {
		t.Fatalf("first use failed: %v", err)
	}

	// Second use: no codes remaining.
	_, err := s.Authenticate(context.Background(), "user@example.com", code)
	if !errors.Is(err, ErrNoRecoveryCodesRemaining) {
		t.Errorf("second use error = %v, want ErrNoRecoveryCodesRemaining", err)
	}
}

func TestGenerateRecoveryCodes(t *testing.T) {
	hasher := NewBcryptHasher(4)
	codes, hashes, err := GenerateRecoveryCodes(hasher, 10)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes error: %v", err)
	}
	if len(codes) != 10 || len(hashes) != 10 {
		t.Fatalf("expected 10 codes and hashes, got %d/%d", len(codes), len(hashes))
	}
	for i, code := range codes {
		if !hasher.Compare(code, hashes[i]) {
			t.Errorf("code[%d] does not match its hash", i)
		}
	}
}
