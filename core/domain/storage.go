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
//	import "github.com/getkayan/kayan/kgorm"
//	import "gorm.io/driver/postgres"
//
//	db, _ := gorm.Open(postgres.Open("postgres://..."), &gorm.Config{})
//	repo := kgorm.New(db)
//
//	// Now use repo with any flow manager
//	reg, login := flow.PasswordAuth(repo, func() any { return &User{} }, "email")
package domain

import (
	"context"

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
//	repo.CreateIdentity(user)
//
//	// Get by ID
//	ident, _ := repo.GetIdentity(func() any { return &User{} }, "123")
//	user := ident.(*User)
//
//	// Find by field
//	ident, _ := repo.FindIdentity(func() any { return &User{} }, map[string]any{"Email": "user@example.com"})
//
// See kgorm package for a reference implementation.
type IdentityStorage interface {
	CredentialStorage
	CreateIdentity(ident any) error
	GetIdentity(factory func() any, id any) (any, error)
	FindIdentity(factory func() any, query map[string]any) (any, error)
	ListIdentities(factory func() any, page, limit int) ([]any, error)
	UpdateIdentity(ident any) error
	DeleteIdentity(factory func() any, id any) error
	CreateCredential(cred any) error
}

type SessionStorage interface {
	CreateSession(s *identity.Session) error
	GetSession(id any) (*identity.Session, error)
	GetSessionByRefreshToken(token string) (*identity.Session, error)
	DeleteSession(id any) error
}

type CredentialStorage interface {
	GetCredentialByIdentifier(identifier string, method string) (*identity.Credential, error)
	UpdateCredentialSecret(ctx context.Context, identityID, method, secret string) error
}

// IDGenerator is a function that generates a new ID.
type IDGenerator func() any

// Hasher defines the interface for password hashing and verification.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) bool
}
