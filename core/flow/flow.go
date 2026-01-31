package flow

import (
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/google/uuid"
)

type FlowType string

const (
	FlowTypeRegistration FlowType = "registration"
	FlowTypeLogin        FlowType = "login"
)

// Flow represents a transient state for an authentication process.
type Flow struct {
	ID        uuid.UUID `json:"id"`
	Type      FlowType  `json:"type"`
	ExpiresAt time.Time `json:"expires_at"`
	Active    bool      `json:"active"`
	IssuedAt  time.Time `json:"issued_at"`

	// Methods could be "password", "oidc", etc.
	Methods []string `json:"methods"`
}

// IdentityRepository is an alias for domain.IdentityStorage.
// This provides a clearer name within the flow package context.
type IdentityRepository = domain.IdentityStorage

func NewFlow(t FlowType, methods []string) *Flow {
	return &Flow{
		ID:        uuid.New(),
		Type:      t,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		Active:    true,
		IssuedAt:  time.Now(),
		Methods:   methods,
	}
}
