package flow

import (
	"context"

	"github.com/getkayan/kayan/internal/identity"
)

// RegistrationStrategy defines how an identity is created for a specific method.
type RegistrationStrategy interface {
	ID() string
	Register(ctx context.Context, traits identity.JSON, secret string) (*identity.Identity, error)
}

// LoginStrategy defines how an identity is authenticated for a specific method.
type LoginStrategy interface {
	ID() string
	Authenticate(ctx context.Context, identifier, secret string) (*identity.Identity, error)
}

// Hook defines a function that runs before or after a flow action.
type Hook func(ctx context.Context, ident *identity.Identity) error
