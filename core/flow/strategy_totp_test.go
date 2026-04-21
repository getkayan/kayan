package flow

import (
	"context"
	"encoding/base32"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

// testTOTPSecret is the fixed base32 TOTP secret used across TOTP unit tests.
const testTOTPSecret = "JBSWY3DPEHPK3PXP"

// mockTOTPRepo is an in-memory TOTPRepository implementation for unit testing.
type mockTOTPRepo struct {
	mu           sync.Mutex
	identities   map[string]any             // "field:value" → identity
	secrets      map[string]string          // identityID → base32 TOTP secret
	usedCounters map[string]map[uint64]bool // identityID → set of used time-step counters
	findErr      error
	secretErr    error
}

func newMockTOTPRepo() *mockTOTPRepo {
	return &mockTOTPRepo{
		identities:   make(map[string]any),
		secrets:      make(map[string]string),
		usedCounters: make(map[string]map[uint64]bool),
	}
}

func (r *mockTOTPRepo) addIdentity(field, value string, ident any, secret string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.identities[field+":"+value] = ident
	if fi, ok := ident.(FlowIdentity); ok {
		id := fmt.Sprintf("%v", fi.GetID())
		r.secrets[id] = secret
		r.usedCounters[id] = make(map[uint64]bool)
	}
}

func (r *mockTOTPRepo) FindIdentityByField(ctx context.Context, field, value string, factory func() any) (any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.findErr != nil {
		return nil, r.findErr
	}
	if ident, ok := r.identities[field+":"+value]; ok {
		return ident, nil
	}
	return nil, errors.New("totp: identity not found")
}

func (r *mockTOTPRepo) FindTOTPSecret(ctx context.Context, identityID any) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.secretErr != nil {
		return "", r.secretErr
	}
	id := fmt.Sprintf("%v", identityID)
	if secret, ok := r.secrets[id]; ok {
		return secret, nil
	}
	return "", errors.New("totp: secret not found")
}

func (r *mockTOTPRepo) MarkTOTPUsed(ctx context.Context, identityID any, counter uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := fmt.Sprintf("%v", identityID)
	if r.usedCounters[id] == nil {
		r.usedCounters[id] = make(map[uint64]bool)
	}
	if r.usedCounters[id][counter] {
		return errors.New("totp: counter already used")
	}
	r.usedCounters[id][counter] = true
	return nil
}

// codeAt generates a TOTP code for the given key at the given time-step offset from now.
func codeAt(key []byte, offsetSteps int64) string {
	s := &TOTPStrategy{}
	now := time.Now().Unix() / 30
	return s.generateCode(key, uint64(now+offsetSteps))
}

func TestTOTPStrategy_ID(t *testing.T) {
	s := NewTOTPStrategy(nil, nil, "")
	if s.ID() != "totp" {
		t.Errorf("ID() = %q, want %q", s.ID(), "totp")
	}
}

func TestTOTPStrategy_Authenticate(t *testing.T) {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(testTOTPSecret)

	tests := []struct {
		name       string
		identifier string
		code       string
		setupRepo  func(*mockTOTPRepo)
		wantErr    error
	}{
		{
			name:       "valid current window code",
			identifier: "user@example.com",
			code:       codeAt(key, 0),
		},
		{
			name:       "valid previous window code (drift tolerance)",
			identifier: "user@example.com",
			code:       codeAt(key, -1),
		},
		{
			name:       "valid next window code (drift tolerance)",
			identifier: "user@example.com",
			code:       codeAt(key, +1),
		},
		{
			name:       "invalid code",
			identifier: "user@example.com",
			code:       "000000",
			wantErr:    ErrTOTPCodeInvalid,
		},
		{
			name:       "stale code outside drift window",
			identifier: "user@example.com",
			code:       codeAt(key, -2),
			wantErr:    ErrTOTPCodeInvalid,
		},
		{
			name:       "identity not found",
			identifier: "unknown@example.com",
			code:       codeAt(key, 0),
			wantErr:    ErrTOTPSecretNotFound,
		},
		{
			name:       "secret not found for identity",
			identifier: "user@example.com",
			code:       codeAt(key, 0),
			setupRepo:  func(r *mockTOTPRepo) { r.secretErr = errors.New("no secret") },
			wantErr:    ErrTOTPSecretNotFound,
		},
		{
			name:       "malformed secret in storage",
			identifier: "user@example.com",
			code:       codeAt(key, 0),
			setupRepo: func(r *mockTOTPRepo) {
				// Overwrite stored secret with invalid base32
				for id := range r.secrets {
					r.secrets[id] = "NOT!VALID!BASE32"
				}
			},
			wantErr: ErrTOTPSecretNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockTOTPRepo()
			ident := &identity.Identity{ID: uuid.NewString()}
			repo.addIdentity("Email", "user@example.com", ident, testTOTPSecret)

			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			s := NewTOTPStrategy(repo, func() any { return &identity.Identity{} }, "Email")
			got, err := s.Authenticate(context.Background(), tt.identifier, tt.code)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Authenticate() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Errorf("Authenticate() unexpected error: %v", err)
			}
			if got == nil {
				t.Error("Authenticate() returned nil identity")
			}
		})
	}
}

func TestTOTPStrategy_Authenticate_ReplayAttack(t *testing.T) {
	repo := newMockTOTPRepo()
	ident := &identity.Identity{ID: uuid.NewString()}
	repo.addIdentity("Email", "user@example.com", ident, testTOTPSecret)

	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(testTOTPSecret)
	code := codeAt(key, 0)

	s := NewTOTPStrategy(repo, func() any { return &identity.Identity{} }, "Email")

	// First use: must succeed.
	_, err := s.Authenticate(context.Background(), "user@example.com", code)
	if err != nil {
		t.Fatalf("first Authenticate() failed: %v", err)
	}

	// Replay: same code, same counter → must fail with ErrTOTPReplay.
	_, err = s.Authenticate(context.Background(), "user@example.com", code)
	if !errors.Is(err, ErrTOTPReplay) {
		t.Errorf("replay Authenticate() error = %v, want ErrTOTPReplay", err)
	}
}

func TestTOTPStrategy_Authenticate_ConcurrentSafe(t *testing.T) {
	repo := newMockTOTPRepo()
	ident := &identity.Identity{ID: uuid.NewString()}
	repo.addIdentity("Email", "user@example.com", ident, testTOTPSecret)

	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(testTOTPSecret)
	code := codeAt(key, 0)

	s := NewTOTPStrategy(repo, func() any { return &identity.Identity{} }, "Email")

	const goroutines = 20
	results := make([]error, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			_, err := s.Authenticate(context.Background(), "user@example.com", code)
			results[idx] = err
		}(i)
	}
	wg.Wait()

	// Exactly one goroutine should succeed; the rest must get ErrTOTPReplay or ErrTOTPCodeInvalid.
	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrTOTPReplay) && !errors.Is(err, ErrTOTPCodeInvalid) {
			t.Errorf("unexpected error from concurrent Authenticate: %v", err)
		}
	}
	if successes != 1 {
		t.Errorf("expected exactly 1 successful authentication, got %d", successes)
	}
}

func TestTOTPStrategy_Verify(t *testing.T) {
	key, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(testTOTPSecret)
	s := &TOTPStrategy{}

	if !s.Verify(testTOTPSecret, codeAt(key, 0)) {
		t.Error("Verify() should return true for current-window code")
	}
	if !s.Verify(testTOTPSecret, codeAt(key, -1)) {
		t.Error("Verify() should return true for previous-window code")
	}
	if !s.Verify(testTOTPSecret, codeAt(key, +1)) {
		t.Error("Verify() should return true for next-window code")
	}
	if s.Verify(testTOTPSecret, "000000") {
		t.Error("Verify() should return false for wrong code")
	}
	if s.Verify("NOT!VALID!BASE32", "000000") {
		t.Error("Verify() should return false for invalid secret")
	}
}
