// Package events provides a unified event system for Kayan.
//
// It supports synchronous and asynchronous event dispatching, allowing decoupled
// communication between core components and external extensions like audit logging,
// webhooks, and analytics.
package events

import (
	"context"
	"time"

	"github.com/getkayan/kayan/core/identity"
)

// Topic defines a unique identifier for event types.
type Topic string

const (
	// Auth Topics
	TopicLoginInitiated   Topic = "auth.login.initiate"
	TopicLoginSuccess     Topic = "auth.login.success"
	TopicLoginFailure     Topic = "auth.login.failure"
	TopicLoginBlocked     Topic = "auth.login.blocked"
	TopicLoginMFARequired Topic = "auth.login.mfa_challenge"
	TopicLogout           Topic = "auth.logout"
	TopicSessionCreated   Topic = "auth.session.created"
	TopicSessionRevoked   Topic = "auth.session.revoked"
	TopicSessionExpired   Topic = "auth.session.expired"
	TopicPasswordChanged  Topic = "auth.password.changed"
	TopicPasswordReset    Topic = "auth.password.reset"

	// Identity Topics
	TopicIdentityCreated   Topic = "identity.created"
	TopicIdentityUpdated   Topic = "identity.updated"
	TopicIdentityDeleted   Topic = "identity.deleted"
	TopicIdentityFailure   Topic = "identity.registration.failure"
	TopicIdentityActivated Topic = "identity.activated"
	TopicIdentitySuspended Topic = "identity.suspended"

	// RBAC Topics
	TopicRoleCreated       Topic = "rbac.role.created"
	TopicRoleUpdated       Topic = "rbac.role.updated"
	TopicRoleDeleted       Topic = "rbac.role.deleted"
	TopicRoleAssigned      Topic = "rbac.role.assigned"
	TopicRoleRevoked       Topic = "rbac.role.revoked"
	TopicPermissionGranted Topic = "rbac.permission.granted"
	TopicPermissionRevoked Topic = "rbac.permission.revoked"

	// Security Topics
	TopicSecurityRateLimited     Topic = "security.rate_limited"
	TopicSecuritySuspiciousLogin Topic = "security.suspicious_login"
	TopicSecurityTokenRevoked    Topic = "security.token.revoked"

	// Tenant Topics
	TopicTenantCreated Topic = "admin.tenant.created"
	TopicTenantUpdated Topic = "admin.tenant.updated"
)

// Event represents a single system event.
type Event struct {
	ID        string        `json:"id"`
	Topic     Topic         `json:"topic"`      // machine-readable topic
	Code      int           `json:"code"`       // machine-readable status code
	ActorID   any           `json:"actor_id"`    // The identity performing the action
	SubjectID any           `json:"subject_id"`  // The affected identity or resource
	Status    string        `json:"status"`      // "success", "failure", "pending"
	Metadata  identity.JSON `json:"metadata"`
	CreatedAt time.Time     `json:"created_at"`
	TenantID  string        `json:"tenant_id,omitempty"`
}

const (
	CodeOK                 = 200
	CodeCreated            = 201
	CodeAccepted           = 202 // e.g. MFA Challenge initiated
	CodeBadRequest         = 400
	CodeUnauthorized       = 401
	CodeForbidden          = 403
	CodeNotFound           = 404
	CodeConflict           = 409
	CodeRateLimited        = 429
	CodeInternalError      = 500
)

// Handler is a function that processes an event.
type Handler func(ctx context.Context, event Event) error

// Dispatcher defines the interface for event publication and subscription.
type Dispatcher interface {
	// Dispatch sends an event to all interested subscribers.
	Dispatch(ctx context.Context, event Event) error

	// Subscribe registers a handler for a specific topic.
	// Use "*" for all topics.
	Subscribe(topic Topic, handler Handler)
}

// NewEvent helper
func NewEvent(topic Topic, code int) Event {
	status := "success"
	if code >= 400 {
		status = "failure"
	}
	return Event{
		Topic:     topic,
		Code:      code,
		CreatedAt: time.Now(),
		Status:    status,
	}
}
