package session

import (
	"errors"
	"time"

	"github.com/getkayan/kayan/internal/domain"
	"github.com/getkayan/kayan/internal/identity"
	"github.com/google/uuid"
)

type SessionRepository = domain.SessionStorage

type Manager struct {
	repo SessionRepository
}

func NewManager(repo SessionRepository) *Manager {
	return &Manager{repo: repo}
}

func (m *Manager) Create(identityID interface{}) (*identity.Session, error) {
	// Re-cast identityID if necessary
	var id uuid.UUID
	switch v := identityID.(type) {
	case uuid.UUID:
		id = v
	case string:
		// Attempt to parse string to UUID
	default:
		return nil, errors.New("invalid identity ID type")
	}

	s := NewSession(id)
	if err := m.repo.CreateSession(s); err != nil {
		return nil, err
	}
	return s, nil
}

func (m *Manager) Validate(sessionID string) (*identity.Session, error) {
	s, err := m.repo.GetSession(sessionID)
	if err != nil {
		return nil, errors.New("invalid session")
	}

	if !s.Active || s.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("session expired or inactive")
	}

	return s, nil
}
