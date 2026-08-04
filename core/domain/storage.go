// Package domain defines core storage interfaces for Kayan IAM.
//
// This package provides the fundamental contracts that storage implementations must fulfill.
// It abstracts persistence operations for identities, sessions, credentials, and tokens,
// allowing developers to use any backend (GORM, MongoDB, Redis, etc.).
//
// # Interfaces
//
//   - Storage: Composite interface combining all storage operations
//   - IdentityStorage: Identity CRUD and credential management
//   - SessionStorage: Session lifecycle operations
//   - CredentialStorage: Credential lookup and updates
//   - TokenStore: Authentication token management
//
// # Supporting Types
//
//   - IDGenerator: Function type for generating unique identifiers
//   - Hasher: Interface for password hashing and verification
//
// # Example Implementation
//
// See the kgorm package for a complete GORM-based implementation of these interfaces.
//
//	import "github.com/getkayan/kayan/kayan-gorm"
//	import "gorm.io/driver/postgres"
//
//	db, _ := gorm.Open(postgres.Open("postgres://..."), &gorm.Config{})
//	repo := gormstore.New(db)
//
//	// Now use repo with any flow manager
//	reg, login := flow.PasswordAuth(repo, func() any { return &User{} }, "email")
package domain

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/identity"
)

// Storage defines the interface for all persistence operations.
type Storage interface {
	IdentityStorage
	SessionStorage
	CredentialStorage
	audit.AuditStore
	TokenStore
}

// IdentityStorage defines CRUD operations for identities and credentials.
//
// The factory function pattern allows storage implementations to work with any
// identity model type without using generics. The factory returns a pointer to
// an empty instance of the user's model.
//
// Example usage:
//
//	// Create
//	user := &User{ID: "123", Email: "user@example.com"}
//	repo.CreateIdentity(ctx, user)
//
//	// Get by ID
//	ident, _ := repo.GetIdentity(ctx, func() any { return &User{} }, "123")
//	user := ident.(*User)
//
//	// Find by field
//	ident, _ := repo.FindIdentity(ctx, func() any { return &User{} }, map[string]any{"Email": "user@example.com"})
//
// Every method takes a context so a storage implementation can honor
// cancellation and read request-scoped values — the ambient tenant among them.
// Without it, tenant isolation cannot reach the query.
//
// See kgorm package for a reference implementation.
type IdentityStorage interface {
	CredentialStorage
	CreateIdentity(ctx context.Context, ident any) error
	GetIdentity(ctx context.Context, factory func() any, id any) (any, error)
	FindIdentity(ctx context.Context, factory func() any, query map[string]any) (any, error)
	ListIdentities(ctx context.Context, factory func() any, page, limit int) ([]any, error)
	UpdateIdentity(ctx context.Context, ident any) error
	DeleteIdentity(ctx context.Context, factory func() any, id any) error
	CreateCredential(ctx context.Context, cred any) error
}

type SessionStorage interface {
	CreateSession(ctx context.Context, s *identity.Session) error
	GetSession(ctx context.Context, id any) (*identity.Session, error)
	GetSessionByRefreshToken(ctx context.Context, token string) (*identity.Session, error)
	DeleteSession(ctx context.Context, id any) error
}

type CredentialStorage interface {
	GetCredentialByIdentifier(ctx context.Context, identifier string, method string) (*identity.Credential, error)
	UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error
}

// IDGenerator is a function that generates a new ID.
//
// It is for record identifiers, where any scheme works — UUIDv4, UUIDv7,
// ULID, or a database sequence. Use [TokenGenerator] for anything an attacker
// must not be able to predict.
type IDGenerator func() any

// TokenGenerator produces a security token: an authorization code, refresh
// token, magic link, or state value.
//
// Implementations must draw from a cryptographically secure source. Unlike
// [IDGenerator], the output is a credential — a sequential or timestamp-derived
// value here lets an attacker guess a token belonging to someone else. The two
// are separate types so that a generator chosen for readable record IDs cannot
// be wired into a credential path by accident.
type TokenGenerator func() (string, error)

// DefaultTokenBytes is the entropy, in bytes, of tokens from
// [NewTokenGenerator]. 256 bits is well beyond the 128-bit floor RFC 6749
// section 10.10 sets for authorization codes.
const DefaultTokenBytes = 32

// NewTokenGenerator returns a [TokenGenerator] drawing n bytes from
// crypto/rand and encoding them as base64url without padding.
//
// It panics if n is below 16, since fewer than 128 bits is guessable at scale
// and a misconfigured generator should fail at startup rather than issue weak
// credentials.
func NewTokenGenerator(n int) TokenGenerator {
	if n < 16 {
		panic("domain: token generator needs at least 16 bytes of entropy")
	}
	return func() (string, error) {
		buf := make([]byte, n)
		if _, err := rand.Read(buf); err != nil {
			return "", fmt.Errorf("domain: read random bytes: %w", err)
		}
		return base64.RawURLEncoding.EncodeToString(buf), nil
	}
}

// DefaultTokenGenerator produces [DefaultTokenBytes] of entropy from
// crypto/rand.
var DefaultTokenGenerator = NewTokenGenerator(DefaultTokenBytes)

// TokenGeneratorOrDefault returns g, or [DefaultTokenGenerator] when g is nil.
func TokenGeneratorOrDefault(g TokenGenerator) TokenGenerator {
	if g == nil {
		return DefaultTokenGenerator
	}
	return g
}

// Hasher defines the interface for password hashing and verification.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) bool
}
