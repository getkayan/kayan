package flow

import (
	"context"

	"github.com/getkayan/kayan/identity"
)

// FlowIdentity defines the minimum interface that any identity model must satisfy.
type FlowIdentity interface {
	GetID() any
	SetID(any)
}

// TraitSource is an optional interface for models that support Kayan's dynamic Traits.
type TraitSource interface {
	GetTraits() identity.JSON
	SetTraits(identity.JSON)
}

// CredentialSource is an optional interface for models that support Kayan's discrete Credentials table.
type CredentialSource interface {
	GetCredentials() []identity.Credential
	SetCredentials([]identity.Credential)
}

// RegistrationStrategy defines how an identity is created for a specific method.
type RegistrationStrategy interface {
	ID() string
	Register(ctx context.Context, traits identity.JSON, secret string) (any, error)
}

// LoginStrategy defines how an identity is authenticated for a specific method.
type LoginStrategy interface {
	ID() string
	Authenticate(ctx context.Context, identifier, secret string) (any, error)
}

// Hook defines a function that runs before or after a flow action.
type Hook func(ctx context.Context, ident any) error
