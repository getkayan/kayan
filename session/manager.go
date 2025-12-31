package session

import (
	"errors"
	"time"

	"github.com/getkayan/kayan/domain"
	"github.com/getkayan/kayan/identity"
)

type SessionRepository[T any] = domain.SessionStorage[T]

type Manager[T any] struct {
	repo SessionRepository[T]
}

func NewManager[T any](repo SessionRepository[T]) *Manager[T] {
	return &Manager[T]{repo: repo}
}

func (m *Manager[T]) Create(sessionID, identityID T) (*identity.Session[T], error) {
	s := NewSession(sessionID, identityID)
	if err := m.repo.CreateSession(s); err != nil {
		return nil, err
	}
	return s, nil
}

func (m *Manager[T]) Validate(sessionID string) (*identity.Session[T], error) {
	s, err := m.repo.GetSession(sessionID)
	if err != nil {
		return nil, errors.New("invalid session")
	}

	if !s.Active || s.ExpiresAt.Before(time.Now()) {
		return nil, errors.New("session expired or inactive")
	}

	return s, nil
}
