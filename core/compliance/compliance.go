// Package compliance provides enterprise compliance controls for Kayan IAM.
//
// This package implements security and privacy controls aligned with SOC 2, ISO 27001,
// and GDPR requirements. It provides data retention management, field-level encryption,
// and security HTTP headers.
//
// # Features
//
//   - Data retention policies with configurable TTLs for audit logs, sessions, consents
//   - Automatic cleanup manager for GDPR-compliant data purging
//   - AES-256-GCM field-level encryption for sensitive data
//   - Security headers middleware (CSP, HSTS, X-Frame-Options, etc.)
//   - Per-tenant retention policy overrides
//
// # Data Retention
//
// The RetentionManager handles automatic cleanup based on configurable policies:
//
//	policy := &compliance.RetentionPolicy{
//	    AuditLogDays:       365,  // SOC 2: 1 year
//	    SessionHistoryDays: 90,
//	    ConsentRecordDays:  1825, // GDPR: 5 years
//	    FailedLoginDays:    30,
//	}
//	manager := compliance.NewRetentionManager(store, policy)
//	manager.RunCleanup(ctx) // Periodic cleanup job
//
// # Field-Level Encryption
//
// Sensitive data can be encrypted at rest:
//
//	enc, _ := compliance.NewAESEncryption(key)
//	ciphertext, _ := enc.Encrypt([]byte(ssn))
//	plaintext, _ := enc.Decrypt(ciphertext)
//
// # Security Headers
//
// Apply security headers to HTTP responses:
//
//	mux.Use(compliance.SecurityHeadersMiddleware(nil)) // Uses defaults
package compliance

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ---- Retention Policy ----

// RetentionPolicy defines data retention rules for compliance.
type RetentionPolicy struct {
	// TenantID for tenant-specific policies (empty = global).
	TenantID string

	// AuditLogDays is how long to keep audit logs (SOC 2 recommends 1 year).
	AuditLogDays int

	// SessionHistoryDays is how long to keep session history.
	SessionHistoryDays int

	// ConsentRecordDays is how long to keep consent records.
	ConsentRecordDays int

	// FailedLoginDays is how long to keep failed login records.
	FailedLoginDays int

	// DeletedUserDays is how long to keep soft-deleted user data.
	DeletedUserDays int
}

// DefaultRetentionPolicy returns SOC 2 / ISO 27001 aligned defaults.
func DefaultRetentionPolicy() *RetentionPolicy {
	return &RetentionPolicy{
		AuditLogDays:       365,  // 1 year
		SessionHistoryDays: 90,   // 3 months
		ConsentRecordDays:  1825, // 5 years (GDPR)
		FailedLoginDays:    30,   // 1 month
		DeletedUserDays:    30,   // Grace period before permanent deletion
	}
}

// ---- Retention Manager ----

// RetentionStore interface for data cleanup.
type RetentionStore interface {
	// PurgeAuditLogs deletes audit logs older than the specified date.
	PurgeAuditLogs(ctx context.Context, olderThan time.Time) (int64, error)

	// PurgeSessions deletes expired sessions older than the specified date.
	PurgeSessions(ctx context.Context, olderThan time.Time) (int64, error)

	// PurgeConsents deletes consent records older than the specified date.
	PurgeConsents(ctx context.Context, olderThan time.Time) (int64, error)

	// PurgeFailedLogins deletes failed login records older than the specified date.
	PurgeFailedLogins(ctx context.Context, olderThan time.Time) (int64, error)

	// PurgeDeletedUsers permanently deletes soft-deleted users.
	PurgeDeletedUsers(ctx context.Context, deletedBefore time.Time) (int64, error)
}

// RetentionHooks provides callbacks for retention operations.
type RetentionHooks struct {
	// BeforePurge is called before any purge operation.
	BeforePurge func(ctx context.Context, dataType string, count int64)

	// AfterPurge is called after a purge operation completes.
	AfterPurge func(ctx context.Context, dataType string, count int64, err error)

	// OnError is called when a purge operation fails.
	OnError func(ctx context.Context, dataType string, err error)
}

// RetentionManager handles data retention and cleanup.
type RetentionManager struct {
	store    RetentionStore
	policies map[string]*RetentionPolicy // Keyed by tenant ID, empty string = default
	hooks    RetentionHooks
}

// NewRetentionManager creates a new retention manager.
func NewRetentionManager(store RetentionStore, defaultPolicy *RetentionPolicy) *RetentionManager {
	if defaultPolicy == nil {
		defaultPolicy = DefaultRetentionPolicy()
	}

	return &RetentionManager{
		store: store,
		policies: map[string]*RetentionPolicy{
			"": defaultPolicy,
		},
	}
}

// SetPolicy sets a tenant-specific retention policy.
func (m *RetentionManager) SetPolicy(tenantID string, policy *RetentionPolicy) {
	m.policies[tenantID] = policy
}

// SetHooks sets retention hooks.
func (m *RetentionManager) SetHooks(hooks RetentionHooks) {
	m.hooks = hooks
}

// GetPolicy retrieves the policy for a tenant (falls back to default).
func (m *RetentionManager) GetPolicy(tenantID string) *RetentionPolicy {
	if policy, ok := m.policies[tenantID]; ok {
		return policy
	}
	return m.policies[""]
}

// RunCleanup executes all retention cleanup operations.
func (m *RetentionManager) RunCleanup(ctx context.Context) (*CleanupReport, error) {
	policy := m.GetPolicy("")
	now := time.Now()

	report := &CleanupReport{
		StartTime: now,
	}

	// Audit logs
	if policy.AuditLogDays > 0 {
		cutoff := now.AddDate(0, 0, -policy.AuditLogDays)
		count, err := m.purgeWithHooks(ctx, "audit_logs", func() (int64, error) {
			return m.store.PurgeAuditLogs(ctx, cutoff)
		})
		report.AuditLogsDeleted = count
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("audit_logs: %v", err))
		}
	}

	// Sessions
	if policy.SessionHistoryDays > 0 {
		cutoff := now.AddDate(0, 0, -policy.SessionHistoryDays)
		count, err := m.purgeWithHooks(ctx, "sessions", func() (int64, error) {
			return m.store.PurgeSessions(ctx, cutoff)
		})
		report.SessionsDeleted = count
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("sessions: %v", err))
		}
	}

	// Consents
	if policy.ConsentRecordDays > 0 {
		cutoff := now.AddDate(0, 0, -policy.ConsentRecordDays)
		count, err := m.purgeWithHooks(ctx, "consents", func() (int64, error) {
			return m.store.PurgeConsents(ctx, cutoff)
		})
		report.ConsentsDeleted = count
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("consents: %v", err))
		}
	}

	// Failed logins
	if policy.FailedLoginDays > 0 {
		cutoff := now.AddDate(0, 0, -policy.FailedLoginDays)
		count, err := m.purgeWithHooks(ctx, "failed_logins", func() (int64, error) {
			return m.store.PurgeFailedLogins(ctx, cutoff)
		})
		report.FailedLoginsDeleted = count
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("failed_logins: %v", err))
		}
	}

	// Deleted users
	if policy.DeletedUserDays > 0 {
		cutoff := now.AddDate(0, 0, -policy.DeletedUserDays)
		count, err := m.purgeWithHooks(ctx, "deleted_users", func() (int64, error) {
			return m.store.PurgeDeletedUsers(ctx, cutoff)
		})
		report.DeletedUsersRemoved = count
		if err != nil {
			report.Errors = append(report.Errors, fmt.Sprintf("deleted_users: %v", err))
		}
	}

	report.EndTime = time.Now()
	return report, nil
}

func (m *RetentionManager) purgeWithHooks(ctx context.Context, dataType string, purgeFunc func() (int64, error)) (int64, error) {
	if m.hooks.BeforePurge != nil {
		m.hooks.BeforePurge(ctx, dataType, 0)
	}

	count, err := purgeFunc()

	if m.hooks.AfterPurge != nil {
		m.hooks.AfterPurge(ctx, dataType, count, err)
	}

	if err != nil && m.hooks.OnError != nil {
		m.hooks.OnError(ctx, dataType, err)
	}

	return count, err
}

// CleanupReport summarizes a cleanup operation.
type CleanupReport struct {
	StartTime           time.Time `json:"start_time"`
	EndTime             time.Time `json:"end_time"`
	AuditLogsDeleted    int64     `json:"audit_logs_deleted"`
	SessionsDeleted     int64     `json:"sessions_deleted"`
	ConsentsDeleted     int64     `json:"consents_deleted"`
	FailedLoginsDeleted int64     `json:"failed_logins_deleted"`
	DeletedUsersRemoved int64     `json:"deleted_users_removed"`
	Errors              []string  `json:"errors,omitempty"`
}

// ---- Encryption Provider ----

// EncryptionProvider defines field-level encryption operations.
type EncryptionProvider interface {
	// Encrypt encrypts plaintext.
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt decrypts ciphertext.
	Decrypt(ciphertext []byte) ([]byte, error)

	// RotateKey rotates the encryption key.
	RotateKey(ctx context.Context) error
}

// AESEncryption provides AES-256-GCM encryption.
type AESEncryption struct {
	key []byte // 32 bytes for AES-256
}

// NewAESEncryption creates a new AES encryption provider.
func NewAESEncryption(key []byte) (*AESEncryption, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 requires a 32-byte key")
	}
	return &AESEncryption{key: key}, nil
}

// NewAESEncryptionFromBase64 creates an encryption provider from a base64 key.
func NewAESEncryptionFromBase64(keyBase64 string) (*AESEncryption, error) {
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 key: %w", err)
	}
	return NewAESEncryption(key)
}

// GenerateAESKey generates a random 32-byte key for AES-256.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func (e *AESEncryption) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (e *AESEncryption) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func (e *AESEncryption) RotateKey(ctx context.Context) error {
	// Key rotation requires re-encrypting all data
	// This is typically implemented at the application level
	newKey, err := GenerateAESKey()
	if err != nil {
		return err
	}
	e.key = newKey
	return nil
}

// ---- Security Headers Middleware ----

// SecurityHeadersConfig configures security headers.
type SecurityHeadersConfig struct {
	// ContentSecurityPolicy header value.
	ContentSecurityPolicy string

	// StrictTransportSecurity header value (HSTS).
	StrictTransportSecurity string

	// XContentTypeOptions header value.
	XContentTypeOptions string

	// XFrameOptions header value.
	XFrameOptions string

	// XXSSProtection header value.
	XXSSProtection string

	// ReferrerPolicy header value.
	ReferrerPolicy string

	// PermissionsPolicy header value.
	PermissionsPolicy string

	// Custom headers.
	CustomHeaders map[string]string
}

// DefaultSecurityHeadersConfig returns SOC 2 / ISO 27001 recommended headers.
func DefaultSecurityHeadersConfig() *SecurityHeadersConfig {
	return &SecurityHeadersConfig{
		ContentSecurityPolicy:   "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains; preload",
		XContentTypeOptions:     "nosniff",
		XFrameOptions:           "DENY",
		XXSSProtection:          "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		PermissionsPolicy:       "geolocation=(), microphone=(), camera=()",
	}
}

// SecurityHeadersMiddleware applies security headers to responses.
func SecurityHeadersMiddleware(config *SecurityHeadersConfig) func(next http.Handler) http.Handler {
	if config == nil {
		config = DefaultSecurityHeadersConfig()
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if config.ContentSecurityPolicy != "" {
				w.Header().Set("Content-Security-Policy", config.ContentSecurityPolicy)
			}
			if config.StrictTransportSecurity != "" {
				w.Header().Set("Strict-Transport-Security", config.StrictTransportSecurity)
			}
			if config.XContentTypeOptions != "" {
				w.Header().Set("X-Content-Type-Options", config.XContentTypeOptions)
			}
			if config.XFrameOptions != "" {
				w.Header().Set("X-Frame-Options", config.XFrameOptions)
			}
			if config.XXSSProtection != "" {
				w.Header().Set("X-XSS-Protection", config.XXSSProtection)
			}
			if config.ReferrerPolicy != "" {
				w.Header().Set("Referrer-Policy", config.ReferrerPolicy)
			}
			if config.PermissionsPolicy != "" {
				w.Header().Set("Permissions-Policy", config.PermissionsPolicy)
			}

			for key, value := range config.CustomHeaders {
				w.Header().Set(key, value)
			}

			next.ServeHTTP(w, r)
		})
	}
}
