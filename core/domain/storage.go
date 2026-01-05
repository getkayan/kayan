package domain

import (
	"github.com/getkayan/kayan/core/identity"
)

// Storage defines the interface for all persistence operations.
type Storage interface {
	IdentityStorage
	SessionStorage
	CredentialStorage
}

type IdentityStorage interface {
	CredentialStorage
	CreateIdentity(ident any) error
	GetIdentity(factory func() any, id any) (any, error)
	FindIdentity(factory func() any, query map[string]any) (any, error)
}

type SessionStorage interface {
	CreateSession(s *identity.Session) error
	GetSession(id any) (*identity.Session, error)
	GetSessionByRefreshToken(token string) (*identity.Session, error)
	DeleteSession(id any) error
}

type CredentialStorage interface {
	GetCredentialByIdentifier(identifier string, method string) (*identity.Credential, error)
}

// IDGenerator is a function that generates a new ID.
type IDGenerator func() any

// Hasher defines the interface for password hashing and verification.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) bool
}
