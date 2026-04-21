package mfa

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// Manager provides a unified API for MFA enrollment, challenge, and verification.
// It is method-agnostic and delegates to registered Method implementations.
//
// Usage:
//
//	store := mfa.NewMemoryStore()
//	manager := mfa.NewManager(store, mfa.WithMaxEnrollments(5))
//	manager.RegisterMethod(&TOTPMethod{})
//	manager.RegisterMethod(&SMSOTPMethod{sender: twilioSender})
//
//	// Enroll
//	enrollment, _ := manager.Enroll(ctx, "user-123", "totp")
//	manager.ConfirmEnrollment(ctx, enrollment.ID, "123456")
//
//	// Challenge and verify
//	challenge, _ := manager.Challenge(ctx, "user-123")
//	ok, _ := manager.Verify(ctx, challenge.ID, "654321")
type Manager struct {
	store          MFAStore
	mu             sync.RWMutex
	methods        map[string]Method
	maxEnrollments int
	challengeTTL   time.Duration
}

// ManagerOption configures a Manager.
type ManagerOption func(*Manager)

// WithMaxEnrollments sets the maximum number of MFA enrollments per identity.
// Default is 0 (unlimited).
func WithMaxEnrollments(n int) ManagerOption {
	return func(m *Manager) { m.maxEnrollments = n }
}

// WithChallengeTTL sets the expiration duration for MFA challenges.
// Default is 5 minutes.
func WithChallengeTTL(d time.Duration) ManagerOption {
	return func(m *Manager) { m.challengeTTL = d }
}

// NewManager creates a new MFA manager.
func NewManager(store MFAStore, opts ...ManagerOption) *Manager {
	m := &Manager{
		store:        store,
		methods:      make(map[string]Method),
		challengeTTL: 5 * time.Minute,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// RegisterMethod registers an MFA method with the manager.
func (m *Manager) RegisterMethod(method Method) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.methods[method.ID()] = method
}

// Enroll initiates enrollment for an identity in a specific MFA method.
// Returns the enrollment with method-specific configuration (e.g., TOTP secret URI).
func (m *Manager) Enroll(ctx context.Context, identityID, methodID string) (*Enrollment, error) {
	m.mu.RLock()
	method, ok := m.methods[methodID]
	m.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("mfa: unknown method %q", methodID)
	}

	// Check max enrollments
	if m.maxEnrollments > 0 {
		enrollments, err := m.store.GetEnrollmentsByIdentity(ctx, identityID)
		if err == nil && len(enrollments) >= m.maxEnrollments {
			return nil, fmt.Errorf("mfa: maximum enrollment limit (%d) reached", m.maxEnrollments)
		}
	}

	// Check for existing active enrollment of this method
	enrollments, err := m.store.GetEnrollmentsByIdentity(ctx, identityID)
	if err == nil {
		for _, e := range enrollments {
			if e.MethodID == methodID && e.Status == EnrollmentActive {
				return nil, fmt.Errorf("mfa: method %q already enrolled", methodID)
			}
		}
	}

	// Delegate to method
	enrollment, err := method.Enroll(ctx, identityID)
	if err != nil {
		return nil, fmt.Errorf("mfa: enrollment failed: %w", err)
	}

	if err := m.store.SaveEnrollment(ctx, enrollment); err != nil {
		return nil, fmt.Errorf("mfa: failed to save enrollment: %w", err)
	}

	return enrollment, nil
}

// ConfirmEnrollment verifies and activates a pending enrollment.
// The response is validated against the method (e.g., valid TOTP code).
func (m *Manager) ConfirmEnrollment(ctx context.Context, enrollmentID, response string) error {
	enrollment, err := m.store.GetEnrollment(ctx, enrollmentID)
	if err != nil {
		return fmt.Errorf("mfa: enrollment not found: %w", err)
	}

	if enrollment.Status != EnrollmentPending {
		return fmt.Errorf("mfa: enrollment is not pending (status: %s)", enrollment.Status)
	}

	m.mu.RLock()
	method, ok := m.methods[enrollment.MethodID]
	m.mu.RUnlock()

	if !ok {
		return fmt.Errorf("mfa: method %q not registered", enrollment.MethodID)
	}

	// Create a verification challenge
	challenge := &Challenge{
		ID:           uuid.New().String(),
		EnrollmentID: enrollmentID,
		MethodID:     enrollment.MethodID,
		ExpiresAt:    time.Now().Add(m.challengeTTL),
	}

	ok, err = method.Verify(ctx, enrollment, challenge, response)
	if err != nil {
		return fmt.Errorf("mfa: verification failed: %w", err)
	}
	if !ok {
		return fmt.Errorf("mfa: invalid response")
	}

	// Activate enrollment
	enrollment.Status = EnrollmentActive
	if err := m.store.UpdateEnrollment(ctx, enrollment); err != nil {
		return fmt.Errorf("mfa: failed to activate enrollment: %w", err)
	}

	return nil
}

// Challenge creates an MFA challenge for an identity using the first active enrollment.
func (m *Manager) Challenge(ctx context.Context, identityID string) (*Challenge, error) {
	enrollments, err := m.store.GetEnrollmentsByIdentity(ctx, identityID)
	if err != nil {
		return nil, fmt.Errorf("mfa: failed to get enrollments: %w", err)
	}

	for _, enrollment := range enrollments {
		if enrollment.Status == EnrollmentActive {
			return m.ChallengeWithMethod(ctx, identityID, enrollment.MethodID)
		}
	}

	return nil, fmt.Errorf("mfa: no active enrollment found for identity %s", identityID)
}

// ChallengeWithMethod creates an MFA challenge for a specific method.
func (m *Manager) ChallengeWithMethod(ctx context.Context, identityID, methodID string) (*Challenge, error) {
	m.mu.RLock()
	method, ok := m.methods[methodID]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("mfa: method %q not registered", methodID)
	}

	// Find active enrollment for this method
	enrollments, err := m.store.GetEnrollmentsByIdentity(ctx, identityID)
	if err != nil {
		return nil, fmt.Errorf("mfa: failed to get enrollments: %w", err)
	}

	var enrollment *Enrollment
	for _, e := range enrollments {
		if e.MethodID == methodID && e.Status == EnrollmentActive {
			enrollment = e
			break
		}
	}

	if enrollment == nil {
		return nil, fmt.Errorf("mfa: no active enrollment for method %q", methodID)
	}

	challenge, err := method.Challenge(ctx, enrollment)
	if err != nil {
		return nil, fmt.Errorf("mfa: challenge creation failed: %w", err)
	}

	if err := m.store.SaveChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("mfa: failed to save challenge: %w", err)
	}

	return challenge, nil
}

// Verify checks the user's response against a pending challenge.
func (m *Manager) Verify(ctx context.Context, challengeID, response string) (bool, error) {
	challenge, err := m.store.GetChallenge(ctx, challengeID)
	if err != nil {
		return false, fmt.Errorf("mfa: challenge not found: %w", err)
	}

	if challenge.ExpiresAt.Before(time.Now()) {
		m.store.DeleteChallenge(ctx, challengeID)
		return false, fmt.Errorf("mfa: challenge expired")
	}

	// Get the enrollment for this challenge
	enrollment, err := m.store.GetEnrollment(ctx, challenge.EnrollmentID)
	if err != nil {
		return false, fmt.Errorf("mfa: enrollment not found: %w", err)
	}

	m.mu.RLock()
	method, ok := m.methods[challenge.MethodID]
	m.mu.RUnlock()
	if !ok {
		return false, fmt.Errorf("mfa: method %q not registered", challenge.MethodID)
	}

	ok, err = method.Verify(ctx, enrollment, challenge, response)
	if err != nil {
		return false, fmt.Errorf("mfa: verification failed: %w", err)
	}

	// Consume challenge (one-time use)
	m.store.DeleteChallenge(ctx, challengeID)

	return ok, nil
}

// ListEnrollments returns all MFA enrollments for an identity.
func (m *Manager) ListEnrollments(ctx context.Context, identityID string) ([]*Enrollment, error) {
	return m.store.GetEnrollmentsByIdentity(ctx, identityID)
}

// DisableMethod disables an MFA enrollment.
func (m *Manager) DisableMethod(ctx context.Context, enrollmentID string) error {
	enrollment, err := m.store.GetEnrollment(ctx, enrollmentID)
	if err != nil {
		return fmt.Errorf("mfa: enrollment not found: %w", err)
	}

	enrollment.Status = EnrollmentDisabled
	return m.store.UpdateEnrollment(ctx, enrollment)
}

// GenerateRecoveryCodes generates one-time-use backup codes for an identity.
// Plaintext codes are returned once to the caller and bcrypt-hashed before persistence.
func (m *Manager) GenerateRecoveryCodes(ctx context.Context, identityID string, count int) ([]string, error) {
	if count <= 0 {
		count = 10
	}

	codes := make([]string, count)
	storedCodes := make([]string, count)
	for i := 0; i < count; i++ {
		code, err := generateRecoveryCode()
		if err != nil {
			return nil, fmt.Errorf("mfa: failed to generate recovery code: %w", err)
		}
		codes[i] = code

		hash, err := hashRecoveryCode(code)
		if err != nil {
			return nil, fmt.Errorf("mfa: failed to hash recovery code: %w", err)
		}
		storedCodes[i] = hash
	}

	if err := m.store.SaveRecoveryCodes(ctx, identityID, storedCodes); err != nil {
		return nil, fmt.Errorf("mfa: failed to save recovery codes: %w", err)
	}

	return codes, nil
}

// VerifyRecoveryCode checks and consumes a recovery code.
// Returns true if the code was valid and consumed.
func (m *Manager) VerifyRecoveryCode(ctx context.Context, identityID, code string) (bool, error) {
	codes, err := m.store.GetRecoveryCodes(ctx, identityID)
	if err != nil {
		return false, fmt.Errorf("mfa: failed to get recovery codes: %w", err)
	}

	// Normalize the code (case-insensitive, strip dashes)
	normalizedInput := strings.ToUpper(strings.ReplaceAll(code, "-", ""))

	for _, stored := range codes {
		matched, err := matchRecoveryCode(normalizedInput, stored)
		if err != nil {
			return false, fmt.Errorf("mfa: failed to verify recovery code: %w", err)
		}
		if matched {
			// Consume the code
			if err := m.store.ConsumeRecoveryCode(ctx, identityID, stored); err != nil {
				return false, err
			}
			return true, nil
		}
	}

	return false, nil
}

// generateRecoveryCode creates a cryptographically random recovery code in XXXX-XXXX format.
func generateRecoveryCode() (string, error) {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	hex := strings.ToUpper(hex.EncodeToString(bytes))
	return hex[:4] + "-" + hex[4:], nil
}

func hashRecoveryCode(code string) (string, error) {
	normalized := normalizeRecoveryCode(code)
	hash, err := bcrypt.GenerateFromPassword([]byte(normalized), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

func matchRecoveryCode(normalizedInput, stored string) (bool, error) {
	if strings.HasPrefix(stored, "$2") {
		err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(normalizedInput))
		if err == nil {
			return true, nil
		}
		if err == bcrypt.ErrMismatchedHashAndPassword {
			return false, nil
		}
		return false, err
	}

	// Backward-compatible plaintext comparison for existing stores.
	normalizedStored := normalizeRecoveryCode(stored)
	return subtle.ConstantTimeCompare([]byte(normalizedInput), []byte(normalizedStored)) == 1, nil
}

func normalizeRecoveryCode(code string) string {
	return strings.ToUpper(strings.ReplaceAll(code, "-", ""))
}
