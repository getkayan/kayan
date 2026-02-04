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

type IdentityStorage interface {
	CredentialStorage
	CreateIdentity(ident any) error
	GetIdentity(factory func() any, id any) (any, error)
	FindIdentity(factory func() any, query map[string]any) (any, error)
	ListIdentities(factory func() any, page, limit int) ([]any, error)
	UpdateIdentity(ident any) error
	DeleteIdentity(id any) error
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
