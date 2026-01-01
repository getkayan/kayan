package session

import (
	"errors"
	"time"

	"github.com/getkayan/kayan/domain"
	"github.com/getkayan/kayan/identity"
)

type SessionRepository = domain.SessionStorage

type Manager struct {
	repo SessionRepository
}

func NewManager(repo SessionRepository) *Manager {
	return &Manager{repo: repo}
}

func (m *Manager) Create(sessionID, identityID any) (*identity.Session, error) {
	s := NewSession(sessionID, identityID)
	if err := m.repo.CreateSession(s); err != nil {
		return nil, err
	}
	return s, nil
}

func (m *Manager) Validate(sessionID any) (*identity.Session, error) {
	s, err := m.repo.GetSession(sessionID)
	if err != nil {
		return nil, errors.New("invalid session")
	}

	if !s.Active || s.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("session expired or inactive")
	}

	return s, nil
}
