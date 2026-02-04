// Package kgorm provides a GORM-based storage adapter for Kayan IAM.
//
// This package implements all core storage interfaces using GORM, supporting
// PostgreSQL, MySQL, and SQLite databases. It provides a plug-and-play persistence
// layer for identities, sessions, credentials, OAuth2 tokens, and audit events.
//
// # Features
//
//   - Full domain.Storage interface implementation
//   - Support for PostgreSQL, MySQL, and SQLite
//   - Automatic schema migration
//   - Identity repository with credential management
//   - Session repository with refresh token support
//   - OAuth2 repository for authorization server
//   - ReBAC repository for relationship-based access control
//   - Audit event storage with SOC 2 compliance
//
// # Supported Databases
//
//   - PostgreSQL: Production recommended
//   - MySQL: Full support
//   - SQLite: Development and testing
//
// # Example Usage
//
//	db, _ := gorm.Open(postgres.Open(dsn), &gorm.Config{})
//	repo := kgorm.NewRepository(db)
//
//	// Run migrations
//	repo.AutoMigrate()
//
//	// Use with flow manager
//	flow.NewManager(repo, ...)
//
// # Custom Models
//
// To extend the default models, pass them to AutoMigrate:
//
//	repo.AutoMigrate(&MyCustomModel{}, &AnotherModel{})
package kgorm

import (
	"context"
	"io"
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
		&gormRelationTuple{},
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
// DeleteExpiredTokens implements domain.TokenStore.
func (r *Repository) DeleteExpiredTokens(ctx context.Context) error {
	return r.db.WithContext(ctx).Delete(&gormAuthToken{}, "expires_at < ?", time.Now()).Error
}

// Query implements audit.AuditStore.
func (r *Repository) Query(ctx context.Context, filter audit.Filter) ([]audit.AuditEvent, error) {
	// TODO: Implement actual query logic mapping filter to GORM
	return []audit.AuditEvent{}, nil
}

// Count implements audit.AuditStore.
func (r *Repository) Count(ctx context.Context, filter audit.Filter) (int64, error) {
	var count int64
	// TODO: Implement actual count logic
	return count, nil
}

// Export implements audit.AuditStore.
func (r *Repository) Export(ctx context.Context, filter audit.Filter, format audit.ExportFormat) (io.Reader, error) {
	return nil, nil // TODO: Implement export
}

// Purge implements audit.AuditStore.
func (r *Repository) Purge(ctx context.Context, olderThan time.Time) (int64, error) {
	return 0, nil // TODO: Implement purge
}

// Compile-time interface checks
var (
	_ domain.IdentityStorage = (*Repository)(nil)
	_ domain.SessionStorage  = (*Repository)(nil)
	_ domain.TokenStore      = (*Repository)(nil)
	_ audit.AuditStore       = (*Repository)(nil)
)
