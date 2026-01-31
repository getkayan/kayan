package kgorm

import (
	"context"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Repository is a facade that combines all sub-repositories.
// It implements domain.Storage by embedding specialized repositories.
type Repository struct {
	*IdentityRepository
	*SessionRepository
	*OAuth2Repository
	db *gorm.DB
}

// NewRepository creates a new Repository with all sub-repositories initialized.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{
		IdentityRepository: NewIdentityRepository(db),
		SessionRepository:  NewSessionRepository(db),
		OAuth2Repository:   NewOAuth2Repository(db),
		db:                 db,
	}
}

// DB returns the underlying GORM database connection.
func (r *Repository) DB() *gorm.DB {
	return r.db
}

func init() {
	Register("sqlite", sqlite.Open)
	Register("postgres", postgres.Open)
	Register("mysql", mysql.Open)
}

// AutoMigrate runs database migrations for all GORM models.
func (r *Repository) AutoMigrate(models ...any) error {
	baseModels := []any{
		&gormIdentity{},
		&gormCredential{},
		&gormSession{},
		&gormClient{},
		&gormAuthCode{},
		&gormRefreshToken{},
		&gormAuditEvent{},
		&gormAuthToken{},
	}
	allModels := append(baseModels, models...)
	return r.db.AutoMigrate(allModels...)
}

// SaveEvent implements audit.AuditStore.
func (r *Repository) SaveEvent(ctx context.Context, event *audit.AuditEvent) error {
	ge := fromCoreAuditEvent(event)
	if ge.ID == "" {
		ge.ID = uuid.New().String()
	}
	if ge.CreatedAt.IsZero() {
		ge.CreatedAt = time.Now()
	}
	return r.db.WithContext(ctx).Save(ge).Error
}

// SaveToken implements domain.TokenStore.
func (r *Repository) SaveToken(ctx context.Context, token *domain.AuthToken) error {
	gt := fromCoreAuthToken(token)
	return r.db.WithContext(ctx).Save(gt).Error
}

// GetToken implements domain.TokenStore.
func (r *Repository) GetToken(ctx context.Context, token string) (*domain.AuthToken, error) {
	var gt gormAuthToken
	if err := r.db.WithContext(ctx).First(&gt, "token = ?", token).Error; err != nil {
		return nil, err
	}
	return toCoreAuthToken(&gt), nil
}

// DeleteToken implements domain.TokenStore.
func (r *Repository) DeleteToken(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Delete(&gormAuthToken{}, "token = ?", token).Error
}

// DeleteExpiredTokens implements domain.TokenStore.
func (r *Repository) DeleteExpiredTokens(ctx context.Context) error {
	return r.db.WithContext(ctx).Delete(&gormAuthToken{}, "expires_at < ?", time.Now()).Error
}

// Compile-time interface checks
var (
	_ domain.IdentityStorage = (*Repository)(nil)
	_ domain.SessionStorage  = (*Repository)(nil)
	_ domain.TokenStore      = (*Repository)(nil)
	_ audit.AuditStore       = (*Repository)(nil)
)
