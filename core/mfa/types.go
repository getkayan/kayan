// Package mfa provides unified Multi-Factor Authentication orchestration for Kayan IAM.
//
// This package decouples MFA enrollment, challenge, and verification from specific
// authentication strategies. It provides a method-agnostic MFA manager that can work
// with TOTP, SMS OTP, WebAuthn, or any custom MFA method.
//
// # Architecture
//
// The mfa package is standalone with zero dependencies on core/flow or core/session.
// It defines its own Method interface that MFA implementations must satisfy.
//
// # Key Concepts
//
//   - Method: An MFA method (TOTP, SMS OTP, WebAuthn, etc.) that can be enrolled and challenged
//   - Enrollment: A record of an MFA method configured for an identity
//   - Challenge: A pending verification request that the identity must respond to
//   - Recovery Codes: One-time-use backup codes for when primary MFA methods are unavailable
//
// # Usage
//
//	store := mfa.NewMemoryStore()
//	manager := mfa.NewManager(store)
//	manager.RegisterMethod(&TOTPMethod{})
//
//	// Enroll a user in TOTP
//	enrollment, _ := manager.Enroll(ctx, "user-123", "totp")
//	// enrollment.Config contains the TOTP secret URI
//
//	// Confirm enrollment with a valid code
//	manager.ConfirmEnrollment(ctx, enrollment.ID, "123456")
//
//	// Generate a challenge on login
//	challenge, _ := manager.Challenge(ctx, "user-123")
//
//	// Verify the challenge
//	ok, _ := manager.Verify(ctx, challenge.ID, "654321")
package mfa

import (
	"context"
	"time"
)

// Method represents an MFA method that can be enrolled and challenged.
// Implementations handle the specific logic for each MFA type (TOTP, SMS OTP, etc.).
//
// The Method interface is defined here (not in core/flow) to keep the mfa package
// standalone. Adapters in core/flow can wrap existing strategies to implement this.
type Method interface {
	// ID returns the unique identifier for this method (e.g., "totp", "sms_otp", "webauthn").
	ID() string

	// Enroll initiates enrollment for an identity. Returns enrollment configuration
	// (e.g., TOTP secret URI, phone number confirmation).
	Enroll(ctx context.Context, identityID string) (*Enrollment, error)

	// Challenge creates a new challenge for a confirmed enrollment.
	Challenge(ctx context.Context, enrollment *Enrollment) (*Challenge, error)

	// Verify checks the user's response against the challenge.
	Verify(ctx context.Context, enrollment *Enrollment, challenge *Challenge, response string) (bool, error)
}

// EnrollmentStatus represents the state of an MFA enrollment.
type EnrollmentStatus string

const (
	// EnrollmentPending indicates enrollment has been initiated but not confirmed.
	EnrollmentPending EnrollmentStatus = "pending"
	// EnrollmentActive indicates enrollment is confirmed and active.
	EnrollmentActive EnrollmentStatus = "active"
	// EnrollmentDisabled indicates enrollment has been disabled.
	EnrollmentDisabled EnrollmentStatus = "disabled"
)

// Enrollment represents a configured MFA method for an identity.
type Enrollment struct {
	ID         string           `json:"id"`
	IdentityID string           `json:"identity_id"`
	MethodID   string           `json:"method_id"`
	Status     EnrollmentStatus `json:"status"`
	Config     any              `json:"config,omitempty"` // Method-specific config (TOTP secret URI, etc.)
	CreatedAt  time.Time        `json:"created_at"`
}

// Challenge represents a pending MFA verification request.
type Challenge struct {
	ID           string    `json:"id"`
	EnrollmentID string    `json:"enrollment_id"`
	MethodID     string    `json:"method_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	Metadata     any       `json:"metadata,omitempty"` // Method-specific hint (masked phone, etc.)
}

// MFAStore defines the interface for persisting MFA enrollments, challenges, and recovery codes.
type MFAStore interface {
	// Enrollment operations
	SaveEnrollment(ctx context.Context, enrollment *Enrollment) error
	GetEnrollment(ctx context.Context, id string) (*Enrollment, error)
	GetEnrollmentsByIdentity(ctx context.Context, identityID string) ([]*Enrollment, error)
	UpdateEnrollment(ctx context.Context, enrollment *Enrollment) error
	DeleteEnrollment(ctx context.Context, id string) error

	// Challenge operations
	SaveChallenge(ctx context.Context, challenge *Challenge) error
	GetChallenge(ctx context.Context, id string) (*Challenge, error)
	DeleteChallenge(ctx context.Context, id string) error

	// Recovery code operations
	SaveRecoveryCodes(ctx context.Context, identityID string, codes []string) error
	GetRecoveryCodes(ctx context.Context, identityID string) ([]string, error)
	ConsumeRecoveryCode(ctx context.Context, identityID, code string) error
}
