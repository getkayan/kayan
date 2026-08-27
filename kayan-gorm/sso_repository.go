package gormstore

import (
	"context"
	"errors"
	"time"

	"github.com/getkayan/kayan/core/session"
	"github.com/getkayan/kayan/core/tenant"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type gormSSOSession struct {
	ID         string `gorm:"primaryKey"`
	TenantId   string `gorm:"uniqueIndex:idx_sso_identity;not null"`
	IdentityID string `gorm:"uniqueIndex:idx_sso_identity;not null"`
	CreatedAt  time.Time
	ExpiresAt  time.Time        `gorm:"index;not null"`
	Active     bool             `gorm:"not null"`
	Apps       []gormAppSession `gorm:"foreignKey:SSOID;constraint:OnDelete:CASCADE"`
}

func (gormSSOSession) TableName() string        { return "sso_sessions" }
func (s *gormSSOSession) TenantID() string      { return s.TenantId }
func (s *gormSSOSession) SetTenantID(id string) { s.TenantId = id }

type gormAppSession struct {
	SessionID string    `gorm:"primaryKey"`
	SSOID     string    `gorm:"uniqueIndex:idx_sso_app;not null"`
	AppID     string    `gorm:"uniqueIndex:idx_sso_app;not null"`
	CreatedAt time.Time `gorm:"not null"`
}

func (gormAppSession) TableName() string { return "sso_app_sessions" }

// SSORepository is the optional GORM implementation of session.SSOStore.
type SSORepository struct{ db *gorm.DB }

// NewSSORepository creates a GORM-backed SSO store.
func NewSSORepository(db *gorm.DB) *SSORepository { return &SSORepository{db: db} }

func (r *SSORepository) CreateOrJoinSSOSession(ctx context.Context, candidate *session.SSOSession) (*session.SSOSession, error) {
	for attempt := 0; attempt < 3; attempt++ {
		tenantID := tenant.IDFromContext(ctx)
		var result *session.SSOSession
		err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			var existing gormSSOSession
			err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Preload("Apps").
				Where("tenant_id = ? AND identity_id = ?", tenantID, candidate.IdentityID).First(&existing).Error
			if errors.Is(err, gorm.ErrRecordNotFound) {
				model := fromSSOSession(candidate, tenantID)
				if err := tx.Create(&model).Error; err != nil {
					return err
				}
				result = cloneCoreSSO(candidate)
				return nil
			}
			if err != nil {
				return err
			}
			if !existing.Active || !existing.ExpiresAt.After(candidate.CreatedAt) {
				if err := tx.Delete(&gormAppSession{}, "sso_id = ?", existing.ID).Error; err != nil {
					return err
				}
				if err := tx.Delete(&existing).Error; err != nil {
					return err
				}
				model := fromSSOSession(candidate, tenantID)
				if err := tx.Create(&model).Error; err != nil {
					return err
				}
				result = cloneCoreSSO(candidate)
				return nil
			}
			app := candidate.AppSessions[0]
			for _, current := range existing.Apps {
				if current.AppID == app.AppID {
					result = toSSOSession(&existing)
					return nil
				}
			}
			if err := tx.Create(&gormAppSession{SessionID: app.SessionID, SSOID: existing.ID, AppID: app.AppID, CreatedAt: app.CreatedAt}).Error; err != nil {
				return err
			}
			existing.Apps = append(existing.Apps, gormAppSession{SessionID: app.SessionID, SSOID: existing.ID, AppID: app.AppID, CreatedAt: app.CreatedAt})
			result = toSSOSession(&existing)
			return nil
		})
		if err == nil {
			return result, nil
		}
		if attempt == 2 {
			return nil, storageError("create or join SSO session", err)
		}
	}
	return nil, errors.New("gormstore: create or join SSO session failed")
}

func (r *SSORepository) GetSSOSession(ctx context.Context, id string) (*session.SSOSession, error) {
	var model gormSSOSession
	if err := r.db.WithContext(ctx).Preload("Apps").First(&model, "id = ? AND tenant_id = ?", id, tenant.IDFromContext(ctx)).Error; err != nil {
		return nil, storageError("get SSO session", err)
	}
	return toSSOSession(&model), nil
}

func (r *SSORepository) GetSSOSessionByIdentity(ctx context.Context, identityID string) (*session.SSOSession, error) {
	var model gormSSOSession
	if err := r.db.WithContext(ctx).Preload("Apps").Where("tenant_id = ? AND identity_id = ? AND active = ?", tenant.IDFromContext(ctx), identityID, true).First(&model).Error; err != nil {
		return nil, storageError("get SSO session by identity", err)
	}
	return toSSOSession(&model), nil
}

func (r *SSORepository) JoinSSOSession(ctx context.Context, id string, app session.AppSession) (*session.AppSession, error) {
	var result *session.AppSession
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current gormSSOSession
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&current, "id = ? AND tenant_id = ?", id, tenant.IDFromContext(ctx)).Error; err != nil {
			return err
		}
		if !current.Active {
			return session.ErrSSOInactive
		}
		if !app.CreatedAt.Before(current.ExpiresAt) {
			return session.ErrSSOExpired
		}
		var existing gormAppSession
		err := tx.Where("sso_id = ? AND app_id = ?", id, app.AppID).First(&existing).Error
		if err == nil {
			result = &session.AppSession{AppID: existing.AppID, SessionID: existing.SessionID, CreatedAt: existing.CreatedAt}
			return nil
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return err
		}
		if err := tx.Create(&gormAppSession{SessionID: app.SessionID, SSOID: id, AppID: app.AppID, CreatedAt: app.CreatedAt}).Error; err != nil {
			return err
		}
		copy := app
		result = &copy
		return nil
	})
	if err != nil {
		return nil, storageError("join SSO session", err)
	}
	return result, nil
}

func (r *SSORepository) LeaveSSOSession(ctx context.Context, id, appID string) error {
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current gormSSOSession
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&current, "id = ? AND tenant_id = ?", id, tenant.IDFromContext(ctx)).Error; err != nil {
			return err
		}
		result := tx.Delete(&gormAppSession{}, "sso_id = ? AND app_id = ?", id, appID)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return session.ErrSSOAppNotFound
		}
		var count int64
		if err := tx.Model(&gormAppSession{}).Where("sso_id = ?", id).Count(&count).Error; err != nil {
			return err
		}
		if count == 0 {
			return tx.Model(&gormSSOSession{}).Where("id = ? AND tenant_id = ?", id, tenant.IDFromContext(ctx)).Update("active", false).Error
		}
		return nil
	})
}

func (r *SSORepository) DeactivateSSOSession(ctx context.Context, id string) ([]session.AppSession, error) {
	var apps []session.AppSession
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current gormSSOSession
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).Preload("Apps").First(&current, "id = ? AND tenant_id = ?", id, tenant.IDFromContext(ctx)).Error; err != nil {
			return err
		}
		apps = toSSOSession(&current).AppSessions
		return tx.Model(&current).Update("active", false).Error
	})
	if err != nil {
		return nil, storageError("deactivate SSO session", err)
	}
	return apps, nil
}

func (r *SSORepository) DeleteSSOSession(ctx context.Context, id string) error {
	return storageError("delete SSO session", r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var current gormSSOSession
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).First(&current, "id = ? AND tenant_id = ?", id, tenant.IDFromContext(ctx)).Error; err != nil {
			return err
		}
		if err := tx.Delete(&gormAppSession{}, "sso_id = ?", id).Error; err != nil {
			return err
		}
		return tx.Delete(&gormSSOSession{}, "id = ? AND tenant_id = ?", id, tenant.IDFromContext(ctx)).Error
	}))
}

func fromSSOSession(value *session.SSOSession, tenantID string) gormSSOSession {
	model := gormSSOSession{ID: value.ID, TenantId: tenantID, IdentityID: value.IdentityID, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, Active: value.Active}
	for _, app := range value.AppSessions {
		model.Apps = append(model.Apps, gormAppSession{SessionID: app.SessionID, SSOID: value.ID, AppID: app.AppID, CreatedAt: app.CreatedAt})
	}
	return model
}

func toSSOSession(value *gormSSOSession) *session.SSOSession {
	result := &session.SSOSession{ID: value.ID, IdentityID: value.IdentityID, CreatedAt: value.CreatedAt, ExpiresAt: value.ExpiresAt, Active: value.Active}
	for _, app := range value.Apps {
		result.AppSessions = append(result.AppSessions, session.AppSession{AppID: app.AppID, SessionID: app.SessionID, CreatedAt: app.CreatedAt})
	}
	return result
}

func cloneCoreSSO(value *session.SSOSession) *session.SSOSession {
	clone := *value
	clone.AppSessions = append([]session.AppSession(nil), value.AppSessions...)
	return &clone
}

var _ session.SSOStore = (*SSORepository)(nil)
