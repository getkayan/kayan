package kgorm

import (
	"github.com/getkayan/kayan/core/identity"
	"gorm.io/gorm"
)

// SessionRepository handles session persistence.
type SessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository creates a new SessionRepository.
func NewSessionRepository(db *gorm.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) CreateSession(s *identity.Session) error {
	return r.db.Create(s).Error
}

func (r *SessionRepository) GetSession(id any) (*identity.Session, error) {
	var s identity.Session
	if err := r.db.First(&s, "id = ?", id).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SessionRepository) GetSessionByRefreshToken(token string) (*identity.Session, error) {
	var s identity.Session
	if err := r.db.Where("refresh_token = ?", token).First(&s).Error; err != nil {
		return nil, err
	}
	return &s, nil
}

func (r *SessionRepository) DeleteSession(id any) error {
	return r.db.Delete(&identity.Session{}, "id = ?", id).Error
}
