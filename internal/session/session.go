package session

import (
	"time"

	"github.com/getkayan/kayan/internal/identity"
	"github.com/google/uuid"
)

type Session = identity.Session

func NewSession(identityID uuid.UUID) *identity.Session {
	return &identity.Session{
		ID:         uuid.New(),
		IdentityID: identityID,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		IssuedAt:   time.Now(),
		Active:     true,
	}
}
