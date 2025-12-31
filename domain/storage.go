package domain

import (
	"github.com/getkayan/kayan/identity"
)

// Storage defines the interface for all persistence operations.
type Storage[T any] interface {
	IdentityStorage[T]
	SessionStorage[T]
	CredentialStorage[T]
}

type IdentityStorage[T any] interface {
	CredentialStorage[T]
	CreateIdentity(id *identity.Identity[T]) error
	GetIdentity(id string) (*identity.Identity[T], error)
	// Add Update/Delete as needed
}

type SessionStorage[T any] interface {
	CreateSession(s *identity.Session[T]) error
	GetSession(id string) (*identity.Session[T], error)
	DeleteSession(id string) error
}

type CredentialStorage[T any] interface {
	GetCredentialByIdentifier(identifier string, method string) (*identity.Credential[T], error)
}

// IDGenerator is a function that generates a new ID of type T.
type IDGenerator[T any] func() T

// Hasher defines the interface for password hashing and verification.
type Hasher interface {
	Hash(password string) (string, error)
	Compare(password, hash string) bool
}
