// Package consent provides GDPR-compliant consent management for Kayan IAM.
//
// This package enables tracking user consent for various data processing purposes,
// supporting both GDPR (EU) and CCPA (California) privacy requirements. It provides
// consent granting, revocation, history tracking, and data export capabilities.
//
// # Features
//
//   - Predefined consent purposes (marketing, analytics, third-party, etc.)
//   - Custom purpose support for application-specific needs
//   - Consent versioning for policy change tracking
//   - Essential purposes that cannot be revoked
//   - Full consent history for audit trails
//   - GDPR-compliant data export
//   - Automatic consent expiration
//
// # Predefined Purposes
//
//   - PurposeMarketing: Marketing communications
//   - PurposeAnalytics: Usage analytics
//   - PurposeThirdParty: Third-party data sharing
//   - PurposePersonalization: Personalized experiences
//   - PurposeEssential: Required for service (cannot be revoked)
//
// # Example Usage
//
//	manager := consent.NewManager(store, "v1.2.0",
//	    consent.WithEssentialPurposes(consent.PurposeEssential),
//	)
//
//	// Grant consent
//	_, err := manager.Grant(ctx, &consent.ConsentRequest{
//	    IdentityID: userID,
//	    Purpose:    consent.PurposeMarketing,
//	    Granted:    true,
//	    Source:     "registration",
//	})
//
//	// Check consent
//	hasConsent, _ := manager.Check(ctx, userID, consent.PurposeMarketing)
//
//	// Export for GDPR request
//	export, _ := manager.ExportConsents(ctx, userID)
package consent

import (
	"context"
	"encoding/json"
	"time"
)

// Purpose defines the type of consent being requested.
// Developers can define custom purposes by using string values.
type Purpose string

// Predefined consent purposes (GDPR/CCPA aligned).
const (
	PurposeMarketing       Purpose = "marketing"
	PurposeAnalytics       Purpose = "analytics"
	PurposeThirdParty      Purpose = "third_party_sharing"
	PurposePersonalization Purpose = "personalization"
	PurposeEssential       Purpose = "essential"       // Cannot be revoked
	PurposeCommunications  Purpose = "communications"  // Email/SMS notifications
	PurposeDataProcessing  Purpose = "data_processing" // General data processing
)

// Consent represents a user's consent decision for a specific purpose.
type Consent struct {
	ID         string    `json:"id"`
	IdentityID string    `json:"identity_id"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Purpose    Purpose   `json:"purpose"`
	Granted    bool      `json:"granted"`
	GrantedAt  time.Time `json:"granted_at,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	ExpiresAt  time.Time `json:"expires_at,omitempty"`
	Version    string    `json:"version"` // Consent policy version
	Source     string    `json:"source"`  // e.g., "registration", "settings", "api"
	IPAddress  string    `json:"ip_address"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// Optional metadata for custom fields
	Metadata json.RawMessage `json:"metadata,omitempty"`
}

// ConsentRequest represents a request to grant or revoke consent.
type ConsentRequest struct {
	IdentityID string          `json:"identity_id"`
	Purpose    Purpose         `json:"purpose"`
	Granted    bool            `json:"granted"`
	Source     string          `json:"source"`
	IPAddress  string          `json:"ip_address"`
	UserAgent  string          `json:"user_agent"`
	ExpiresIn  time.Duration   `json:"expires_in,omitempty"` // Optional expiry
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

// ---- Store Interface ----

// Store defines the interface for consent persistence.
type Store interface {
	// Save creates or updates a consent record.
	Save(ctx context.Context, consent *Consent) error

	// Get retrieves the current consent for a specific purpose.
	Get(ctx context.Context, identityID string, purpose Purpose) (*Consent, error)

	// GetAll retrieves all consents for an identity.
	GetAll(ctx context.Context, identityID string) ([]*Consent, error)

	// GetHistory retrieves the consent history for audit purposes.
	GetHistory(ctx context.Context, identityID string, purpose Purpose) ([]*Consent, error)

	// Delete removes all consent records for an identity (GDPR erasure).
	Delete(ctx context.Context, identityID string) error

	// FindExpired returns consents that have expired.
	FindExpired(ctx context.Context, before time.Time) ([]*Consent, error)
}

// ---- Hooks ----

// Hooks provides extension points for consent lifecycle events.
type Hooks struct {
	// BeforeGrant is called before granting consent.
	BeforeGrant func(ctx context.Context, req *ConsentRequest) error

	// AfterGrant is called after consent is granted.
	AfterGrant func(ctx context.Context, consent *Consent)

	// BeforeRevoke is called before revoking consent.
	BeforeRevoke func(ctx context.Context, consent *Consent) error

	// AfterRevoke is called after consent is revoked.
	AfterRevoke func(ctx context.Context, consent *Consent)

	// OnExpired is called when a consent expires.
	OnExpired func(ctx context.Context, consent *Consent)

	// ValidatePurpose validates if a purpose is allowed.
	// Return error to reject the consent request.
	ValidatePurpose func(ctx context.Context, purpose Purpose) error

	// IDGenerator generates consent IDs.
	IDGenerator func() string
}

// ---- Manager ----

// Manager handles consent operations with hooks and validation.
type Manager struct {
	store   Store
	hooks   Hooks
	version string // Current consent policy version

	// EssentialPurposes are purposes that cannot be revoked.
	EssentialPurposes []Purpose
}

// ManagerOption configures the Manager.
type ManagerOption func(*Manager)

// NewManager creates a new consent manager.
func NewManager(store Store, version string, opts ...ManagerOption) *Manager {
	m := &Manager{
		store:             store,
		version:           version,
		EssentialPurposes: []Purpose{PurposeEssential},
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// WithHooks sets lifecycle hooks.
func WithHooks(hooks Hooks) ManagerOption {
	return func(m *Manager) {
		m.hooks = hooks
	}
}

// WithEssentialPurposes sets purposes that cannot be revoked.
func WithEssentialPurposes(purposes ...Purpose) ManagerOption {
	return func(m *Manager) {
		m.EssentialPurposes = purposes
	}
}

// Grant records a consent grant.
func (m *Manager) Grant(ctx context.Context, req *ConsentRequest) (*Consent, error) {
	// Validate purpose
	if m.hooks.ValidatePurpose != nil {
		if err := m.hooks.ValidatePurpose(ctx, req.Purpose); err != nil {
			return nil, err
		}
	}

	// Before grant hook
	if m.hooks.BeforeGrant != nil {
		if err := m.hooks.BeforeGrant(ctx, req); err != nil {
			return nil, err
		}
	}

	now := time.Now()
	consent := &Consent{
		IdentityID: req.IdentityID,
		Purpose:    req.Purpose,
		Granted:    true,
		GrantedAt:  now,
		Version:    m.version,
		Source:     req.Source,
		IPAddress:  req.IPAddress,
		UserAgent:  req.UserAgent,
		Metadata:   req.Metadata,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if m.hooks.IDGenerator != nil {
		consent.ID = m.hooks.IDGenerator()
	}

	if req.ExpiresIn > 0 {
		consent.ExpiresAt = now.Add(req.ExpiresIn)
	}

	if err := m.store.Save(ctx, consent); err != nil {
		return nil, err
	}

	// After grant hook
	if m.hooks.AfterGrant != nil {
		m.hooks.AfterGrant(ctx, consent)
	}

	return consent, nil
}

// Revoke revokes a previously granted consent.
func (m *Manager) Revoke(ctx context.Context, identityID string, purpose Purpose) error {
	// Check if essential
	for _, ep := range m.EssentialPurposes {
		if ep == purpose {
			return ErrEssentialConsent
		}
	}

	consent, err := m.store.Get(ctx, identityID, purpose)
	if err != nil {
		return err
	}

	// Before revoke hook
	if m.hooks.BeforeRevoke != nil {
		if err := m.hooks.BeforeRevoke(ctx, consent); err != nil {
			return err
		}
	}

	now := time.Now()
	consent.Granted = false
	consent.RevokedAt = now
	consent.UpdatedAt = now

	if err := m.store.Save(ctx, consent); err != nil {
		return err
	}

	// After revoke hook
	if m.hooks.AfterRevoke != nil {
		m.hooks.AfterRevoke(ctx, consent)
	}

	return nil
}

// Check returns whether consent is currently granted for a purpose.
func (m *Manager) Check(ctx context.Context, identityID string, purpose Purpose) (bool, error) {
	// Essential purposes are always granted
	for _, ep := range m.EssentialPurposes {
		if ep == purpose {
			return true, nil
		}
	}

	consent, err := m.store.Get(ctx, identityID, purpose)
	if err != nil {
		return false, nil // No consent = not granted
	}

	// Check if expired
	if !consent.ExpiresAt.IsZero() && time.Now().After(consent.ExpiresAt) {
		return false, nil
	}

	return consent.Granted, nil
}

// GetAll retrieves all consents for an identity.
func (m *Manager) GetAll(ctx context.Context, identityID string) ([]*Consent, error) {
	return m.store.GetAll(ctx, identityID)
}

// GetHistory retrieves consent history for audit.
func (m *Manager) GetHistory(ctx context.Context, identityID string, purpose Purpose) ([]*Consent, error) {
	return m.store.GetHistory(ctx, identityID, purpose)
}

// DeleteAll removes all consents for an identity (for GDPR erasure).
func (m *Manager) DeleteAll(ctx context.Context, identityID string) error {
	return m.store.Delete(ctx, identityID)
}

// ProcessExpired handles expired consents.
func (m *Manager) ProcessExpired(ctx context.Context) error {
	expired, err := m.store.FindExpired(ctx, time.Now())
	if err != nil {
		return err
	}

	for _, consent := range expired {
		consent.Granted = false
		consent.UpdatedAt = time.Now()
		m.store.Save(ctx, consent)

		if m.hooks.OnExpired != nil {
			m.hooks.OnExpired(ctx, consent)
		}
	}

	return nil
}

// UpdateVersion updates the policy version.
// This can trigger re-consent requirements.
func (m *Manager) UpdateVersion(version string) {
	m.version = version
}

// ---- Errors ----

// Common errors.
type ConsentError struct {
	Code    string
	Message string
}

func (e *ConsentError) Error() string {
	return e.Message
}

var (
	ErrConsentNotFound  = &ConsentError{Code: "consent_not_found", Message: "consent record not found"}
	ErrEssentialConsent = &ConsentError{Code: "essential_consent", Message: "essential consent cannot be revoked"}
	ErrConsentExpired   = &ConsentError{Code: "consent_expired", Message: "consent has expired"}
	ErrInvalidPurpose   = &ConsentError{Code: "invalid_purpose", Message: "invalid consent purpose"}
)

// ---- GDPR Helpers ----

// GDPRExport represents exportable user data for GDPR right to access.
type GDPRExport struct {
	IdentityID string     `json:"identity_id"`
	Consents   []*Consent `json:"consents"`
	ExportedAt time.Time  `json:"exported_at"`
	Format     string     `json:"format"`
}

// ExportConsents creates a GDPR-compliant export of consent data.
func (m *Manager) ExportConsents(ctx context.Context, identityID string) (*GDPRExport, error) {
	consents, err := m.store.GetAll(ctx, identityID)
	if err != nil {
		return nil, err
	}

	return &GDPRExport{
		IdentityID: identityID,
		Consents:   consents,
		ExportedAt: time.Now(),
		Format:     "json",
	}, nil
}
