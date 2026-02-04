// Package core provides the foundation for Kayan IAM.
//
// Kayan is a headless, non-generic, extensible Identity & Access Management (IAM)
// library for Go. It allows you to use your own database schema (BYOS - Bring Your
// Own Schema) while providing powerful authentication and authorization primitives.
//
// # Key Features
//
//   - BYOS (Bring Your Own Schema): Works with any existing user model
//   - Strategy Pattern: Mix and match authentication methods (Password, OIDC, WebAuthn, SAML, Magic Link, TOTP)
//   - Flexible Sessions: JWT (stateless), Database (revocable), or custom
//   - Authorization: RBAC, ABAC, Hybrid, and ReBAC support
//   - Multi-Tenancy: Full tenant isolation
//   - Enterprise Ready: Audit logging, rate limiting, account lockout
//
// # Subpackages
//
//   - flow: Authentication flows and strategies
//   - session: Session management
//   - rbac: Role-based access control
//   - policy: ABAC and hybrid policy engine
//   - rebac: Relationship-based access control
//   - tenant: Multi-tenancy support
//   - audit: Audit logging
//   - saml: SAML 2.0 SSO support
//   - oidc: OpenID Connect support
//
// # Quick Start
//
//	// 1. Define your model
//	type User struct {
//	    ID           string `gorm:"primaryKey"`
//	    Email        string `gorm:"uniqueIndex"`
//	    PasswordHash string
//	}
//	func (u *User) GetID() any   { return u.ID }
//	func (u *User) SetID(id any) { u.ID = id.(string) }
//
//	// 2. Setup Kayan
//	repo := kgorm.NewRepository(db)
//	hasher := flow.NewBcryptHasher(10)
//	pwStrategy := flow.NewPasswordStrategy(repo, hasher, "", factory)
//	pwStrategy.MapFields([]string{"Email"}, "PasswordHash")
//
// See https://github.com/getkayan/kayan for full documentation.
package core

import (
	"github.com/getkayan/kayan/core/identity"
	"github.com/google/uuid"
)

// ID is the default identifier type used by Kayan (UUID).
// You can use any identifier type with Kayan by implementing the FlowIdentity interface.
type ID = uuid.UUID

// Identity is the default identity type.
// Typically you will define your own identity model and implement FlowIdentity.
type Identity = identity.DefaultIdentity

// Session represents an authenticated session.
// Contains the session ID, identity ID, and optional metadata.
type Session = identity.DefaultSession

// Credential represents stored authentication credentials.
// Used for WebAuthn, TOTP, and other multi-credential scenarios.
type Credential = identity.DefaultCredential
