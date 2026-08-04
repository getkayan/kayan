package oauth2

import (
	"context"
	"sync"
	"time"
)

// RevocationStore persists revoked token identifiers for stateless JWT invalidation.
type RevocationStore interface {
	// RevokeToken marks a token as revoked until its natural expiry.
	RevokeToken(ctx context.Context, jti string, expiresAt time.Time) error

	// IsRevoked checks whether a token has been revoked.
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// MemoryRevocationStore is an in-memory RevocationStore suitable for testing
// and single-instance deployments.
type MemoryRevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]time.Time // jti → expiry
}

// NewMemoryRevocationStore creates a new in-memory revocation store.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{
		revoked: make(map[string]time.Time),
	}
}

func (s *MemoryRevocationStore) RevokeToken(_ context.Context, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[jti] = expiresAt
	return nil
}

func (s *MemoryRevocationStore) IsRevoked(_ context.Context, jti string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[jti]
	return ok, nil
}

// CleanExpired removes entries whose expiry has passed, freeing memory.
func (s *MemoryRevocationStore) CleanExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for jti, exp := range s.revoked {
		if exp.Before(now) {
			delete(s.revoked, jti)
		}
	}
}
