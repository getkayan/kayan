// Package session provides session management for Kayan IAM.
//
// The session package supports multiple session strategies:
//
//   - JWT (Stateless): Tokens contain all session data, no server storage needed
//   - Database: Sessions stored in database, fully revocable
//   - Custom: Implement the Strategy interface for custom storage
//
// # JWT Sessions
//
// Use JWT for stateless, scalable session management:
//
//	strategy := session.NewHS256Strategy([]byte("secret"), 24*time.Hour)
//	manager := session.NewManager(strategy)
//
//	// Create session after login
//	sess, err := manager.Create(sessionID, identityID)
//	token := sess.Token // Send to client
//
//	// Validate on each request
//	sess, err := manager.Validate(token)
//
// # Token Rotation
//
// For enhanced security, use access/refresh token rotation:
//
//	strategy := session.NewRotationStrategy(
//	    session.NewHS256Strategy(secret, 15*time.Minute),  // Short-lived access
//	    session.NewHS256Strategy(secret, 7*24*time.Hour),  // Long-lived refresh
//	)
//
// # Logout Notifications
//
// Register notifiers to handle logout events (cleanup, audit, etc.):
//
//	manager.AddLogoutNotifier(myNotifier)
package session

import (
	"context"
	"fmt"

	"github.com/getkayan/kayan/core/identity"
)

// Manager handles session lifecycle operations.
// It delegates to a configured Strategy for the actual session storage and validation.
type Manager struct {
	strategy  Strategy
	notifiers []LogoutNotifier
}

// LogoutNotifier is called when a session is deleted/logged out.
// Use this to trigger cleanup, audit logging, or other side effects.
type LogoutNotifier interface {
	NotifyLogout(sid string, identityID string) error
}

// NewManager creates a new session Manager with the given strategy.
func NewManager(strategy Strategy) *Manager {
	return &Manager{strategy: strategy}
}

func (m *Manager) AddLogoutNotifier(n LogoutNotifier) {
	m.notifiers = append(m.notifiers, n)
}

func (m *Manager) Create(ctx context.Context, sessionID, identityID any) (*identity.Session, error) {
	return m.strategy.Create(ctx, sessionID, identityID)
}

// Rotate issues a new session and ends the one the request arrived with.
//
// Call it whenever the authority of a session changes -- on login, and again
// after a second factor or any step-up. Create alone does not do this: it
// takes a caller-supplied identifier and invalidates nothing, so the previous
// session stays live alongside the new one.
//
// Two failures follow from that, and Rotate is the answer to both.
//
// Session fixation: an attacker who can plant a session identifier in a
// victim's browser -- a URL parameter, a cookie set on a shared subdomain --
// and gets the victim to authenticate under it ends up holding a live
// authenticated session, because the identifier the victim logged in with is
// the one the attacker chose.
//
// Privilege upgrade: a partial session issued after the first factor stays
// valid once the second completes, so the pre-MFA token can be replayed
// against the step-up endpoint that trusts it.
//
// priorSessionID may be nil or empty for an ordinary login with nothing to
// replace, and an identifier the strategy does not recognise is ignored: a
// stale or forged value is not a live session, so there is nothing to end and
// no reason to refuse the login.
//
// A revocation that fails is reported and no session is returned. Handing back
// a new session while the old one survives is the fixation window staying open
// while the caller believes it closed.
func (m *Manager) Rotate(ctx context.Context, priorSessionID, sessionID, identityID any) (*identity.Session, error) {
	if priorSessionID != nil && fmt.Sprintf("%v", priorSessionID) != "" {
		// Only end a session that exists. Validate also gives us the identity
		// for the logout notifiers.
		if prior, err := m.strategy.Validate(ctx, priorSessionID); err == nil {
			sid := fmt.Sprintf("%v", priorSessionID)
			for _, n := range m.notifiers {
				// As in Delete: a notifier failure must not stop the session
				// being revoked, which is the part that ends it here.
				_ = n.NotifyLogout(sid, prior.IdentityID)
			}
			if err := m.strategy.Delete(ctx, priorSessionID); err != nil {
				return nil, fmt.Errorf("session: rotate could not end the previous session: %w", err)
			}
		}
	}

	return m.strategy.Create(ctx, sessionID, identityID)
}

func (m *Manager) Validate(ctx context.Context, sessionID any) (*identity.Session, error) {
	return m.strategy.Validate(ctx, sessionID)
}

func (m *Manager) Refresh(ctx context.Context, refreshToken string) (*identity.Session, error) {
	return m.strategy.Refresh(ctx, refreshToken)
}

// Delete revokes a session and notifies any registered logout notifiers.
//
// Notification is synchronous. Spawning a goroutine per notifier would leave
// every in-flight notification unfinished at shutdown, so a relying party
// would keep a session the user believes they ended.
func (m *Manager) Delete(ctx context.Context, sessionID any) error {
	sess, err := m.strategy.Validate(ctx, sessionID)
	if err == nil {
		sid := fmt.Sprintf("%v", sessionID)
		for _, n := range m.notifiers {
			// A notifier failure must not prevent the local session from being
			// revoked, which is the part that actually ends the session here.
			_ = n.NotifyLogout(sid, sess.IdentityID)
		}
	}
	return m.strategy.Delete(ctx, sessionID)
}
