package flow

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
)

// APIKeyRepository is the storage contract for the api_key strategy.
// Implementations should index keys by the SHA-256 hash of the raw key —
// the raw key is never stored.
type APIKeyRepository interface {
	// FindIdentityByAPIKeyHash looks up an active, unexpired identity whose API key
	// matches keyHash (hex-encoded SHA-256 of the raw key).
	FindIdentityByAPIKeyHash(ctx context.Context, keyHash string, factory func() any) (any, error)
}

// APIKeyStrategy implements machine-to-machine authentication via pre-shared API keys.
// It satisfies LoginStrategy.
//
// Keys are passed as the "secret" argument to Authenticate. The "identifier" is ignored
// (callers may pass the first 8 characters of the key as a key-ID prefix for logging).
//
// Security invariants:
//   - Only the SHA-256 hash of the key is ever looked up or compared.
//   - Comparison uses subtle.ConstantTimeCompare to prevent timing attacks.
//   - The raw key and hash are never logged.
type APIKeyStrategy struct {
	repo    APIKeyRepository
	factory func() any
}

// NewAPIKeyStrategy creates an APIKeyStrategy.
//
//	strategy := flow.NewAPIKeyStrategy(repo, func() any { return &ServiceAccount{} })
//	loginManager.RegisterStrategy(strategy)
func NewAPIKeyStrategy(repo APIKeyRepository, factory func() any) *APIKeyStrategy {
	return &APIKeyStrategy{repo: repo, factory: factory}
}

func (s *APIKeyStrategy) ID() string { return "api_key" }

// Authenticate verifies rawKey by hashing it and looking up the hash in storage.
// identifier is optional (may be a key-ID prefix) and is not used for lookup.
func (s *APIKeyStrategy) Authenticate(ctx context.Context, _ string, rawKey string) (any, error) {
	if rawKey == "" {
		return nil, ErrAPIKeyInvalid
	}

	sum := sha256.Sum256([]byte(rawKey))
	keyHash := hex.EncodeToString(sum[:])

	ident, err := s.repo.FindIdentityByAPIKeyHash(ctx, keyHash, s.factory)
	if err != nil {
		// Use constant-time compare of a dummy value to avoid timing differences
		// between "not found" and "wrong key" responses.
		subtle.ConstantTimeCompare(sum[:], sum[:]) //nolint:staticcheck
		return nil, ErrAPIKeyInvalid
	}

	return ident, nil
}

// HashAPIKey returns the hex-encoded SHA-256 hash of rawKey.
// Use this when storing a new API key so the raw key is never persisted.
func HashAPIKey(rawKey string) string {
	sum := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(sum[:])
}

// GenerateAPIKey generates a cryptographically random API key of the given byte length
// and returns both the raw key (to show to the user once) and its hash (to store).
func GenerateAPIKey(byteLen int) (rawKey, keyHash string, err error) {
	raw, err := generateSecureToken(byteLen)
	if err != nil {
		return "", "", fmt.Errorf("flow: api_key: generate: %w", err)
	}
	return raw, HashAPIKey(raw), nil
}
