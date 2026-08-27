package gormstore

import (
	"context"

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

func (r *SessionRepository) CreateSession(ctx context.Context, s *identity.Session) error {
	return storageError("create session", r.db.WithContext(ctx).Create(s).Error)
}

func (r *SessionRepository) GetSession(ctx context.Context, id any) (*identity.Session, error) {
	var s identity.Session
	if err := r.db.WithContext(ctx).First(&s, "id = ?", id).Error; err != nil {
		return nil, storageError("get session", err)
	}
	return &s, nil
}

func (r *SessionRepository) GetSessionByRefreshToken(ctx context.Context, token string) (*identity.Session, error) {
	var s identity.Session
	if err := r.db.WithContext(ctx).Where("refresh_token = ?", token).First(&s).Error; err != nil {
		return nil, storageError("get session by refresh token", err)
	}
	return &s, nil
}

func (r *SessionRepository) DeleteSession(ctx context.Context, id any) error {
	return storageError("delete session", r.db.WithContext(ctx).Delete(&identity.Session{}, "id = ?", id).Error)
}
