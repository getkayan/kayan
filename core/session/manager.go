package session

import (
	"github.com/getkayan/kayan/core/identity"
)

type Manager struct {
	strategy Strategy
}

func NewManager(strategy Strategy) *Manager {
	return &Manager{strategy: strategy}
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
	return m.strategy.Delete(sessionID)
}
