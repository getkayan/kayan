package session

import (
	"fmt"

	"github.com/getkayan/kayan/core/identity"
)

type Manager struct {
	strategy  Strategy
	notifiers []LogoutNotifier
}

type LogoutNotifier interface {
	NotifyLogout(sid string, identityID string) error
}

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
