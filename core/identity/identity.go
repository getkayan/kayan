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
	"encoding/json"
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
func (i *Identity) MFAConfig() (bool, string)     { return i.MFAEnabled, i.MFASecret }
func (i *Identity) IsVerified() bool              { return i.Verified }
func (i *Identity) MarkVerified(at time.Time) {
	i.Verified = true
	i.VerifiedAt = &at
}

func (i *Identity) RoleNames() []string {
	return unmarshalStringSlice(i.Roles)
}

func (i *Identity) PermissionNames() []string {
	return unmarshalStringSlice(i.Permissions)
}

func (i *Identity) GetRoles() []string {
	return i.RoleNames()
}

func (i *Identity) GetPermissions() []string {
	return i.PermissionNames()
}

// IsEmailVerified checks if the identity has a verified email trait.
func (i *Identity) IsEmailVerified() bool {
	var traits map[string]any
	json.Unmarshal(i.Traits, &traits)
	if verified, ok := traits["email_verified"].(bool); ok {
		return verified
	}
	// Fallback to searching for "email" if it's the primary identifier and verified status is stored elsewhere
	return i.Verified
}

func unmarshalStringSlice(data JSON) []string {
	if len(data) == 0 {
		return []string{}
	}

	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return []string{}
	}

	return values
}

// Linkable defines methods for attaching credentials to an existing identity.
type Linkable interface {
	AddCredential(cred Credential)
	RemoveCredential(id string)
}

func (i *Identity) AddCredential(cred Credential) {
	i.Credentials = append(i.Credentials, cred)
}

func (i *Identity) RemoveCredential(id string) {
	newCreds := make([]Credential, 0, len(i.Credentials))
	for _, c := range i.Credentials {
		if c.ID != id {
			newCreds = append(newCreds, c)
		}
	}
	i.Credentials = newCreds
}

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

// FlowIdentity defines the minimum interface for identity models used in auth flows.
type FlowIdentity interface {
	GetID() any
	SetID(any)
}

// TraitSource provides access to an identity's flexible trait data.
type TraitSource interface {
	GetTraits() JSON
	SetTraits(JSON)
}

// CredentialSource provides access to an identity's authentication credentials.
type CredentialSource interface {
	GetCredentials() []Credential
}

// Mapper defines the interface for mapping conceptual keys to struct fields.
type Mapper interface {
	MapTraits(ident FlowIdentity) (JSON, error)
	UnmapTraits(ident FlowIdentity, traits JSON) error
}
