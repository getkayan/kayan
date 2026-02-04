// Package flow provides authentication flows and strategies for Kayan IAM.
//
// The flow package is the core of Kayan's authentication system. It implements
// a strategy pattern that allows mixing and matching different authentication
// methods while maintaining a consistent interface.
//
// # Strategies
//
// Kayan supports multiple authentication strategies:
//
//   - Password: Traditional username/password with bcrypt or argon2
//   - OIDC: Social login with Google, GitHub, Microsoft, etc.
//   - WebAuthn: Passkeys and FIDO2 hardware keys
//   - Magic Link: Passwordless email authentication
//   - TOTP: Time-based one-time passwords for MFA
//   - SAML 2.0: Enterprise SSO (see saml package)
//
// # BYOS (Bring Your Own Schema)
//
// The key feature of Kayan's flow package is BYOS - you use your existing
// database models. Simply implement the FlowIdentity interface and map
// your fields:
//
//	type User struct {
//	    ID           string `gorm:"primaryKey"`
//	    Email        string `gorm:"uniqueIndex"`
//	    PasswordHash string
//	}
//	func (u *User) GetID() any   { return u.ID }
//	func (u *User) SetID(id any) { u.ID = id.(string) }
//
//	// Map your fields
//	pwStrategy.MapFields([]string{"Email"}, "PasswordHash")
//
// # Registration Flow
//
//	regManager := flow.NewRegistrationManager(repo, factory)
//	regManager.RegisterStrategy(pwStrategy)
//	identity, err := regManager.Submit(ctx, "password", traits, secret)
//
// # Login Flow
//
//	loginManager := flow.NewLoginManager(repo)
//	loginManager.RegisterStrategy(pwStrategy)
//	identity, err := loginManager.Authenticate(ctx, "password", identifier, secret)
//
// # Hooks
//
// Register hooks to run before or after authentication events:
//
//	regManager.OnAfterRegistration(func(ctx context.Context, ident any) error {
//	    // Send welcome email, create profile, etc.
//	    return nil
//	})
package flow

import (
	"time"

	"github.com/getkayan/kayan/core/domain"
	"github.com/google/uuid"
)

// FlowType represents the type of authentication flow.
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
