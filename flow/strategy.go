package flow

import (
	"context"

	"github.com/getkayan/kayan/identity"
)

// RegistrationStrategy defines how an identity is created for a specific method.
type RegistrationStrategy[T any] interface {
	ID() string
	Register(ctx context.Context, traits identity.JSON, secret string) (*identity.Identity[T], error)
}

// LoginStrategy defines how an identity is authenticated for a specific method.
type LoginStrategy[T any] interface {
	ID() string
	Authenticate(ctx context.Context, identifier, secret string) (*identity.Identity[T], error)
}

// Hook defines a function that runs before or after a flow action.
type Hook[T any] func(ctx context.Context, ident *identity.Identity[T]) error
