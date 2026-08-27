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

// Every method queries gormSession rather than identity.Session. The tenant
// isolation callback keys off the model being queried, and only gormSession
// implements tenant.Scoped -- identity.Session is the core type and has no
// tenant field to carry. Querying the core type directly worked, and silently
// crossed tenant boundaries while doing so.

func (r *SessionRepository) CreateSession(ctx context.Context, s *identity.Session) error {
	return storageError("create session", r.db.WithContext(ctx).Create(fromCoreSession(s)).Error)
}

func (r *SessionRepository) GetSession(ctx context.Context, id any) (*identity.Session, error) {
	var s gormSession
	if err := r.db.WithContext(ctx).First(&s, "id = ?", id).Error; err != nil {
		return nil, storageError("get session", err)
	}
	return toCoreSession(&s), nil
}

func (r *SessionRepository) GetSessionByRefreshToken(ctx context.Context, token string) (*identity.Session, error) {
	var s gormSession
	if err := r.db.WithContext(ctx).Where("refresh_token = ?", token).First(&s).Error; err != nil {
		return nil, storageError("get session by refresh token", err)
	}
	return toCoreSession(&s), nil
}

func (r *SessionRepository) DeleteSession(ctx context.Context, id any) error {
	return storageError("delete session", r.db.WithContext(ctx).Delete(&gormSession{}, "id = ?", id).Error)
}

// DeleteSessionsByIdentity implements domain.BulkSessionStorage.
//
// This is what makes a password reset end an attacker's session rather than
// only changing the password they already used.
func (r *SessionRepository) DeleteSessionsByIdentity(ctx context.Context, identityID any) error {
	return storageError("delete sessions by identity",
		r.db.WithContext(ctx).Delete(&gormSession{}, "identity_id = ?", identityID).Error)
}
