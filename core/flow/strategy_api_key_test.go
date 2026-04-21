package flow

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

// ---- mock storage ----

type mockAPIKeyRepo struct {
	mu      sync.RWMutex
	keys    map[string]any // keyHash → identity
	findErr error
}

func newMockAPIKeyRepo() *mockAPIKeyRepo {
	return &mockAPIKeyRepo{keys: make(map[string]any)}
}

func (r *mockAPIKeyRepo) storeKey(rawKey string, ident any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[HashAPIKey(rawKey)] = ident
}

func (r *mockAPIKeyRepo) FindIdentityByAPIKeyHash(ctx context.Context, keyHash string, factory func() any) (any, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.findErr != nil {
		return nil, r.findErr
	}
	if ident, ok := r.keys[keyHash]; ok {
		return ident, nil
	}
	return nil, errors.New("api_key: not found")
}

// ---- tests ----

type stubServiceAccount struct{ id string }

func (a *stubServiceAccount) GetID() any  { return a.id }
func (a *stubServiceAccount) SetID(v any) { a.id = fmt.Sprintf("%v", v) }

func TestAPIKeyStrategy_ID(t *testing.T) {
	s := NewAPIKeyStrategy(nil, nil)
	if s.ID() != "api_key" {
		t.Errorf("ID() = %q, want %q", s.ID(), "api_key")
	}
}

func TestAPIKeyStrategy_Authenticate(t *testing.T) {
	const goodKey = "super-secret-api-key-32-bytes-xx"

	tests := []struct {
		name      string
		rawKey    string
		setupRepo func(*mockAPIKeyRepo)
		wantErr   error
	}{
		{
			name:   "valid key",
			rawKey: goodKey,
		},
		{
			name:    "empty key",
			rawKey:  "",
			wantErr: ErrAPIKeyInvalid,
		},
		{
			name:    "wrong key",
			rawKey:  "totally-wrong-key",
			wantErr: ErrAPIKeyInvalid,
		},
		{
			name:      "repo error",
			rawKey:    goodKey,
			setupRepo: func(r *mockAPIKeyRepo) { r.findErr = errors.New("db down") },
			wantErr:   ErrAPIKeyInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := newMockAPIKeyRepo()
			acct := &stubServiceAccount{id: "sa-1"}
			repo.storeKey(goodKey, acct)
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			s := NewAPIKeyStrategy(repo, func() any { return &stubServiceAccount{} })
			got, err := s.Authenticate(context.Background(), "", tt.rawKey)

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

func TestHashAPIKey_Deterministic(t *testing.T) {
	h1 := HashAPIKey("my-key")
	h2 := HashAPIKey("my-key")
	if h1 != h2 {
		t.Error("HashAPIKey is not deterministic")
	}
	if HashAPIKey("a") == HashAPIKey("b") {
		t.Error("HashAPIKey collision for different inputs")
	}
}

func TestGenerateAPIKey(t *testing.T) {
	raw, hash, err := GenerateAPIKey(32)
	if err != nil {
		t.Fatalf("GenerateAPIKey error: %v", err)
	}
	if raw == "" || hash == "" {
		t.Fatal("empty raw or hash")
	}
	if HashAPIKey(raw) != hash {
		t.Error("hash does not match HashAPIKey(raw)")
	}
}
