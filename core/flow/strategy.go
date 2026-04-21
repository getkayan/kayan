package flow

import (
	"context"
	"time"

	"github.com/getkayan/kayan/core/identity"
)

// FlowIdentity defines the minimum interface that any identity model must satisfy.
//
// All user models must implement this interface to work with Kayan's flow package.
// This is the only required interface — all other interfaces are optional.
//
// Example:
//
//	type User struct {
//	    UserID string `gorm:"primaryKey"`
//	    Email  string `gorm:"uniqueIndex"`
//	}
//
//	func (u *User) GetID() any { return u.UserID }
//	func (u *User) SetID(id any) { u.UserID = id.(string) }
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

// MFAIdentity is an optional interface for identities that support MFA checks.
type MFAIdentity interface {
	MFAConfig() (enabled bool, secret string)
}

// VerificationIdentity is an optional interface for identities that support verification flows.
type VerificationIdentity interface {
	IsVerified() bool
	MarkVerified(time.Time)
}

// RegistrationStrategy defines how an identity is created for a specific method.
//
// Implement this interface to add a new registration method. The strategy is
// responsible for validating traits, hashing secrets, and creating the identity
// record in storage.
//
// Example:
//
//	type MyStrategy struct {
//	    repo IdentityRepository
//	}
//
//	func (s *MyStrategy) ID() string { return "my_method" }
//
//	func (s *MyStrategy) Register(ctx context.Context, traits identity.JSON, secret string) (any, error) {
//	    // 1. Validate traits and secret
//	    // 2. Hash secret if needed
//	    // 3. Create identity in storage
//	    return ident, nil
//	}
type RegistrationStrategy interface {
	ID() string
	Register(ctx context.Context, traits identity.JSON, secret string) (any, error)
}

// LoginStrategy defines how an identity is authenticated for a specific method.
//
// Implement this interface to add a new authentication method. The strategy is
// responsible for looking up the identity, verifying the secret, and returning
// the authenticated identity.
//
// Example:
//
//	type MyStrategy struct {
//	    repo IdentityRepository
//	}
//
//	func (s *MyStrategy) ID() string { return "my_method" }
//
//	func (s *MyStrategy) Authenticate(ctx context.Context, identifier, secret string) (any, error) {
//	    // 1. Look up identity by identifier
//	    // 2. Verify secret (constant-time comparison)
//	    // 3. Return identity on success
//	    return ident, nil
//	}
type LoginStrategy interface {
	ID() string
	Authenticate(ctx context.Context, identifier, secret string) (any, error)
}

// Initiator is an optional interface for login strategies that support a multi-step initiation (e.g. Magic Link, OTP).
type Initiator interface {
	Initiate(ctx context.Context, identifier string) (any, error)
}

// Hook defines a function that runs before or after a flow action.
type Hook func(ctx context.Context, ident any) error
