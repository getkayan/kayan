package core

import (
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

// Default types for convenience
type ID = uuid.UUID
type Identity = identity.DefaultIdentity
type Session = identity.DefaultSession
type Credential = identity.DefaultCredential
