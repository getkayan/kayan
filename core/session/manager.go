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

func (m *Manager) Create(sessionID, identityID any) (*identity.Session, error) {
	return m.strategy.Create(sessionID, identityID)
}

func (m *Manager) Validate(sessionID any) (*identity.Session, error) {
	return m.strategy.Validate(sessionID)
}

func (m *Manager) Refresh(refreshToken string) (*identity.Session, error) {
	return m.strategy.Refresh(refreshToken)
}

func (m *Manager) Delete(sessionID any) error {
	sess, err := m.strategy.Validate(sessionID)
	if err == nil {
		sid := fmt.Sprintf("%v", sessionID)
		for _, n := range m.notifiers {
			go n.NotifyLogout(sid, sess.IdentityID)
		}
	}
	return m.strategy.Delete(sessionID)
}
