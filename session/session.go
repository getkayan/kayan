package session

import (
	"fmt"
	"time"

	"github.com/getkayan/kayan/identity"
)

type Session = identity.Session

func NewSession(sessionID, identityID any) *identity.Session {
	return &identity.Session{
		ID:         fmt.Sprintf("%v", sessionID),
		IdentityID: fmt.Sprintf("%v", identityID),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		IssuedAt:   time.Now(),
		Active:     true,
	}
}
