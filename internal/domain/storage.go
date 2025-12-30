package domain

import (
	"github.com/getkayan/kayan/internal/identity"
)

// Storage defines the interface for all persistence operations.
type Storage interface {
	IdentityStorage
	SessionStorage
	CredentialStorage
}

type IdentityStorage interface {
	CredentialStorage
	CreateIdentity(id *identity.Identity) error
	GetIdentity(id string) (*identity.Identity, error)
	// Add Update/Delete as needed
}

type SessionStorage interface {
	CreateSession(s *identity.Session) error
	GetSession(id string) (*identity.Session, error)
	DeleteSession(id string) error
}

type CredentialStorage interface {
	GetCredentialByIdentifier(identifier string, method string) (*identity.Credential, error)
}

// Hasher defines the interface for password hashing and verification.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) bool
}
