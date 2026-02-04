// Package identity provides core identity types for Kayan IAM.
//
// This package defines the fundamental types for user identities, credentials,
// and sessions. These types serve as defaults that can be used directly or
// extended by implementing your own types with the required interfaces.
//
// # Core Types
//
//   - Identity: User identity with traits (JSON), roles, permissions, and MFA settings
//   - Credential: Authentication credential (password, WebAuthn, TOTP, etc.)
//   - Session: Authenticated session with refresh token support
//   - JSON: Custom type for flexible JSON data storage in various databases
//
// # Identity States
//
// Identities can be in one of several states:
//   - active: Normal operational state
//   - inactive: Disabled but not deleted
//   - locked: Temporarily locked (e.g., too many failed logins)
//   - pending: Awaiting verification
//
// # Schema Validation
//
// The Schema interface allows custom validation of identity traits:
//
//	type MySchema struct{}
//	func (s MySchema) Validate(traits identity.JSON) error {
//	    // Validate required fields, formats, etc.
//	}
package identity

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"time"
)

// Default types for high-level use cases
type DefaultIdentity = Identity
type DefaultCredential = Credential
type DefaultSession = Session

// JSON is a custom type for handling JSON data in various storages.
type JSON []byte

func (j JSON) Value() (driver.Value, error) {
	if len(j) == 0 {
		return nil, nil
	}
	return string(j), nil
}

func (j *JSON) Scan(value interface{}) error {
	if value == nil {
		*j = nil
		return nil
	}
	switch v := value.(type) {
	case []byte:
		*j = append((*j)[0:0], v...)
	case string:
		*j = []byte(v)
	default:
		return errors.New("invalid type for JSON")
	}
	return nil
}

// Identity represents a user identity.
type Identity struct {
	ID          string     `json:"id"`
	Traits      JSON       `json:"traits"`
	Roles       JSON       `json:"roles,omitempty"`
	Permissions JSON       `json:"permissions,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	DeletedAt   *time.Time `json:"-"`
	State       string     `json:"state"` // active, inactive, locked, pending

	MFAEnabled bool   `json:"mfa_enabled"`
	MFASecret  string `json:"-"`

	Verified   bool       `json:"verified"`
	VerifiedAt *time.Time `json:"verified_at"`

	Credentials []Credential `json:"-"`
}

func (i *Identity) GetID() any { return i.ID }
func (i *Identity) SetID(id any) {
	if s, ok := id.(string); ok {
		i.ID = s
	} else {
		i.ID = fmt.Sprintf("%v", id)
	}
}

func (i *Identity) GetTraits() JSON               { return i.Traits }
func (i *Identity) SetTraits(t JSON)              { i.Traits = t }
func (i *Identity) GetCredentials() []Credential  { return i.Credentials }
func (i *Identity) SetCredentials(c []Credential) { i.Credentials = c }

// Credential represents an authentication credential.
type Credential struct {
	ID         string    `json:"id"`
	IdentityID string    `json:"identity_id"`
	Type       string    `json:"type"`
	Identifier string    `json:"identifier"`
	Secret     string    `json:"-"`
	Config     JSON      `json:"config"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// Session represents an authenticated session.
type Session struct {
	ID               string    `json:"id"`
	IdentityID       string    `json:"identity_id"`
	RefreshToken     string    `json:"refresh_token,omitempty"`
	ExpiresAt        time.Time `json:"expires_at"`
	RefreshExpiresAt time.Time `json:"refresh_expires_at,omitempty"`
	IssuedAt         time.Time `json:"issued_at"`
	Active           bool      `json:"active"`
}

// Schema defines the interface for validating identity traits.
type Schema interface {
	Validate(traits JSON) error
}
