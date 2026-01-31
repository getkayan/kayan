package audit

import (
	"context"
	"io"
	"time"

	"github.com/getkayan/kayan/core/identity"
)

// RiskLevel categorizes the severity of audit events for compliance.
type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// AuditEvent represents a structured security event record.
// Designed for SOC 2 / ISO 27001 compliance requirements.
type AuditEvent struct {
	ID        string        `json:"id"`
	Type      string        `json:"type"`       // e.g., "identity.login.success"
	ActorID   string        `json:"actor_id"`   // The identity performing the action
	SubjectID string        `json:"subject_id"` // The affected identity or resource
	Status    string        `json:"status"`     // "success", "failure", "blocked"
	Message   string        `json:"message"`    // Human-readable summary
	Metadata  identity.JSON `json:"metadata"`   // Contextual information (IP, User-Agent, etc.)
	CreatedAt time.Time     `json:"created_at"`

	// Compliance-enhanced fields
	TenantID     string        `json:"tenant_id,omitempty"`
	IPAddress    string        `json:"ip_address,omitempty"`
	UserAgent    string        `json:"user_agent,omitempty"`
	GeoLocation  *GeoLocation  `json:"geo_location,omitempty"`
	DeviceID     string        `json:"device_id,omitempty"`
	SessionID    string        `json:"session_id,omitempty"`
	ResourceType string        `json:"resource_type,omitempty"` // e.g., "identity", "session", "role"
	ResourceID   string        `json:"resource_id,omitempty"`
	OldValue     identity.JSON `json:"old_value,omitempty"` // For change tracking
	NewValue     identity.JSON `json:"new_value,omitempty"`
	Risk         RiskLevel     `json:"risk,omitempty"`
	RequestID    string        `json:"request_id,omitempty"` // For request correlation
}

// GeoLocation represents geographic location data.
type GeoLocation struct {
	Country   string  `json:"country,omitempty"`
	Region    string  `json:"region,omitempty"`
	City      string  `json:"city,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
}

// AuditStore defines the interface for persisting and querying audit events.
type AuditStore interface {
	// SaveEvent persists an audit event.
	SaveEvent(ctx context.Context, event *AuditEvent) error

	// Query returns events matching the filter.
	Query(ctx context.Context, filter Filter) ([]AuditEvent, error)

	// Count returns the number of events matching the filter.
	Count(ctx context.Context, filter Filter) (int64, error)

	// Export exports events in the specified format.
	Export(ctx context.Context, filter Filter, format ExportFormat) (io.Reader, error)

	// Purge deletes events older than the specified time.
	// Returns the number of events deleted.
	Purge(ctx context.Context, olderThan time.Time) (int64, error)
}

// Filter for querying audit events.
type Filter struct {
	TenantID     string
	ActorID      string
	SubjectID    string
	Types        []string
	Statuses     []string
	RiskLevels   []RiskLevel
	ResourceType string
	ResourceID   string
	StartTime    time.Time
	EndTime      time.Time
	IPAddress    string
	SessionID    string
	Limit        int
	Offset       int
	OrderBy      string // "created_at", "-created_at" (desc)
}

// ExportFormat for audit log exports.
type ExportFormat string

const (
	ExportJSON ExportFormat = "json"
	ExportCSV  ExportFormat = "csv"
)

// ---- Predefined Event Types (SOC 2 / ISO 27001 aligned) ----

const (
	// Authentication events
	EventLoginSuccess    = "auth.login.success"
	EventLoginFailure    = "auth.login.failure"
	EventLoginBlocked    = "auth.login.blocked"
	EventLogout          = "auth.logout"
	EventSessionCreated  = "auth.session.created"
	EventSessionRevoked  = "auth.session.revoked"
	EventSessionExpired  = "auth.session.expired"
	EventPasswordChanged = "auth.password.changed"
	EventPasswordReset   = "auth.password.reset"
	EventMFAEnabled      = "auth.mfa.enabled"
	EventMFADisabled     = "auth.mfa.disabled"
	EventMFAChallenge    = "auth.mfa.challenge"

	// Identity lifecycle events
	EventUserCreated   = "identity.created"
	EventUserUpdated   = "identity.updated"
	EventUserDeleted   = "identity.deleted"
	EventUserSuspended = "identity.suspended"
	EventUserActivated = "identity.activated"

	// RBAC events
	EventRoleCreated       = "rbac.role.created"
	EventRoleUpdated       = "rbac.role.updated"
	EventRoleDeleted       = "rbac.role.deleted"
	EventRoleAssigned      = "rbac.role.assigned"
	EventRoleRevoked       = "rbac.role.revoked"
	EventPermissionGranted = "rbac.permission.granted"
	EventPermissionRevoked = "rbac.permission.revoked"

	// Consent events (GDPR compliance)
	EventConsentGranted = "consent.granted"
	EventConsentRevoked = "consent.revoked"
	EventConsentExpired = "consent.expired"

	// Data events (GDPR compliance)
	EventDataAccessed = "data.accessed"
	EventDataExported = "data.exported"
	EventDataDeleted  = "data.deleted"

	// Admin events
	EventAdminAction     = "admin.action"
	EventConfigChanged   = "admin.config.changed"
	EventTenantCreated   = "admin.tenant.created"
	EventTenantUpdated   = "admin.tenant.updated"
	EventTenantSuspended = "admin.tenant.suspended"

	// Security events
	EventRateLimited     = "security.rate_limited"
	EventSuspiciousLogin = "security.suspicious_login"
	EventTokenRevoked    = "security.token.revoked"
)

// ---- Event Builder (Developer-Friendly API) ----

// EventBuilder provides a fluent API for creating audit events.
type EventBuilder struct {
	event *AuditEvent
}

// NewEvent starts building a new audit event.
func NewEvent(eventType string) *EventBuilder {
	return &EventBuilder{
		event: &AuditEvent{
			Type:      eventType,
			CreatedAt: time.Now(),
			Risk:      RiskLow,
		},
	}
}

func (b *EventBuilder) ID(id string) *EventBuilder {
	b.event.ID = id
	return b
}

func (b *EventBuilder) Actor(actorID string) *EventBuilder {
	b.event.ActorID = actorID
	return b
}

func (b *EventBuilder) Subject(subjectID string) *EventBuilder {
	b.event.SubjectID = subjectID
	return b
}

func (b *EventBuilder) Success() *EventBuilder {
	b.event.Status = "success"
	return b
}

func (b *EventBuilder) Failure() *EventBuilder {
	b.event.Status = "failure"
	return b
}

func (b *EventBuilder) Blocked() *EventBuilder {
	b.event.Status = "blocked"
	return b
}

func (b *EventBuilder) Status(status string) *EventBuilder {
	b.event.Status = status
	return b
}

func (b *EventBuilder) Message(msg string) *EventBuilder {
	b.event.Message = msg
	return b
}

func (b *EventBuilder) Tenant(tenantID string) *EventBuilder {
	b.event.TenantID = tenantID
	return b
}

func (b *EventBuilder) IP(ip string) *EventBuilder {
	b.event.IPAddress = ip
	return b
}

func (b *EventBuilder) UserAgent(ua string) *EventBuilder {
	b.event.UserAgent = ua
	return b
}

func (b *EventBuilder) Session(sessionID string) *EventBuilder {
	b.event.SessionID = sessionID
	return b
}

func (b *EventBuilder) Device(deviceID string) *EventBuilder {
	b.event.DeviceID = deviceID
	return b
}

func (b *EventBuilder) Resource(resourceType, resourceID string) *EventBuilder {
	b.event.ResourceType = resourceType
	b.event.ResourceID = resourceID
	return b
}

func (b *EventBuilder) Change(oldValue, newValue identity.JSON) *EventBuilder {
	b.event.OldValue = oldValue
	b.event.NewValue = newValue
	return b
}

func (b *EventBuilder) Risk(level RiskLevel) *EventBuilder {
	b.event.Risk = level
	return b
}

func (b *EventBuilder) Metadata(meta identity.JSON) *EventBuilder {
	b.event.Metadata = meta
	return b
}

func (b *EventBuilder) RequestID(id string) *EventBuilder {
	b.event.RequestID = id
	return b
}

func (b *EventBuilder) Geo(loc *GeoLocation) *EventBuilder {
	b.event.GeoLocation = loc
	return b
}

// Build returns the constructed event.
func (b *EventBuilder) Build() *AuditEvent {
	return b.event
}

// Save persists the event using the provided store.
func (b *EventBuilder) Save(ctx context.Context, store AuditStore) error {
	return store.SaveEvent(ctx, b.event)
}

// ---- Hooks for Audit Customization ----

// Hooks provides extension points for audit behavior.
type Hooks struct {
	// BeforeSave is called before persisting an event.
	// Modify the event or return error to prevent saving.
	BeforeSave func(ctx context.Context, event *AuditEvent) error

	// AfterSave is called after an event is persisted.
	AfterSave func(ctx context.Context, event *AuditEvent)

	// EnrichEvent adds additional data to events (e.g., geo lookup).
	EnrichEvent func(ctx context.Context, event *AuditEvent) error

	// AlertOnRisk is called for high/critical risk events.
	AlertOnRisk func(ctx context.Context, event *AuditEvent)

	// IDGenerator generates event IDs. If nil, store should generate.
	IDGenerator func() string
}

// ---- Logger Wrapper ----

// Logger wraps an AuditStore and applies hooks.
type Logger struct {
	store AuditStore
	hooks Hooks
}

// NewLogger creates a new audit logger.
func NewLogger(store AuditStore, hooks Hooks) *Logger {
	return &Logger{store: store, hooks: hooks}
}

// Log persists an audit event with hooks applied.
func (l *Logger) Log(ctx context.Context, event *AuditEvent) error {
	// Generate ID if needed
	if event.ID == "" && l.hooks.IDGenerator != nil {
		event.ID = l.hooks.IDGenerator()
	}

	// Enrich event
	if l.hooks.EnrichEvent != nil {
		if err := l.hooks.EnrichEvent(ctx, event); err != nil {
			return err
		}
	}

	// Before save hook
	if l.hooks.BeforeSave != nil {
		if err := l.hooks.BeforeSave(ctx, event); err != nil {
			return err
		}
	}

	// Persist
	if err := l.store.SaveEvent(ctx, event); err != nil {
		return err
	}

	// After save hook
	if l.hooks.AfterSave != nil {
		l.hooks.AfterSave(ctx, event)
	}

	// Alert on high risk
	if (event.Risk == RiskHigh || event.Risk == RiskCritical) && l.hooks.AlertOnRisk != nil {
		l.hooks.AlertOnRisk(ctx, event)
	}

	return nil
}

// Query delegates to the store.
func (l *Logger) Query(ctx context.Context, filter Filter) ([]AuditEvent, error) {
	return l.store.Query(ctx, filter)
}

// Store returns the underlying store for direct access.
func (l *Logger) Store() AuditStore {
	return l.store
}
