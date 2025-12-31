package session

import (
	"time"

	"github.com/getkayan/kayan/identity"
)

type Session[T any] = identity.Session[T]

func NewSession[T any](sessionID, identityID T) *identity.Session[T] {
	return &identity.Session[T]{
		ID:         sessionID,
		IdentityID: identityID,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		IssuedAt:   time.Now(),
		Active:     true,
	}
}
