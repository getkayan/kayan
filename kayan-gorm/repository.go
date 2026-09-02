// Package gormstore provides a GORM-based storage adapter for Kayan IAM.
//
// This package implements all core storage interfaces using GORM, supporting
// PostgreSQL, MySQL, and SQLite databases. It provides a plug-and-play persistence
// layer for identities, sessions, credentials, OAuth2 tokens, and audit events.
//
// # Features
//
//   - Full domain.Storage interface implementation
//   - Support for PostgreSQL, MySQL, and SQLite
//   - Versioned SQL migrations for PostgreSQL, MySQL, and SQLite
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
//	repo := gormstore.NewRepository(db)
//
//	// Development: create tables from the Go models.
//	repo.AutoMigrateDev()
//
//	// Production: apply the versioned SQL with your own migration tool.
//	files, _ := gormstore.Migrations(gormstore.DialectPostgres)
//
//	// Use with flow manager
//	flow.NewManager(repo, ...)
//
// # Custom Models
//
// To extend the default models, pass them to AutoMigrateDev:
//
//	repo.AutoMigrateDev(&MyCustomModel{}, &AnotherModel{})
package gormstore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/getkayan/kayan/core/audit"
	"github.com/getkayan/kayan/core/domain"
	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Repository is a facade that combines all sub-repositories.
// It implements domain.Storage by embedding specialized repositories.
//
// Protocol storage lives with its protocol, not here: OAuth 2.0 in
// kayan-oidc-provider/gormstore and SCIM in kayan-scim/gormstore. A
// deployment that only needs password authentication therefore carries no
// OAuth 2.0 or SCIM code at all.
type Repository struct {
	*IdentityRepository
	*SessionRepository
	*SSORepository
	db *gorm.DB
}

// NewRepository creates a new Repository with all sub-repositories initialized.
func NewRepository(db *gorm.DB) *Repository {
	return &Repository{
		IdentityRepository: NewIdentityRepository(db),
		SessionRepository:  NewSessionRepository(db),
		SSORepository:      NewSSORepository(db),
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

// AutoMigrateDev creates or updates tables from the Go models.
//
// For development and tests only. GORM's AutoMigrate cannot drop a column,
// cannot transform existing rows, keeps no record of what it ran, and offers
// no way back — a schema change that turns out to be wrong cannot be
// reversed, and on a table holding accounts that is not recoverable.
//
// Production deployments should apply the versioned SQL from [Migrations]
// with a real migration tool.
func (r *Repository) AutoMigrateDev(models ...any) error {
	baseModels := []any{
		&gormIdentity{},
		&gormCredential{},
		&gormSession{},
		&gormSSOSession{},
		&gormAppSession{},
		&gormAuditEvent{},
		&gormAuthToken{},
		&gormRelationTuple{},
		&RoleAssignment{},
		&RoleDefinition{},
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
//
// Expired tokens are reported as not found. These tokens authenticate password
// recovery, email verification, and magic-link login, so the store filters on
// expiry rather than relying on every caller to re-check it.
func (r *Repository) GetToken(ctx context.Context, token string) (*domain.AuthToken, error) {
	var gt gormAuthToken
	err := r.db.WithContext(ctx).First(&gt, "token = ?", token).Error
	if err != nil {
		return nil, storageError("get token", err)
	}
	if !gt.ExpiresAt.After(time.Now()) {
		return nil, fmt.Errorf("gormstore: get token: %w", domain.ErrExpired)
	}
	return toCoreAuthToken(&gt), nil
}

// ConsumeToken atomically retrieves and deletes a live token of the expected type.
func (r *Repository) ConsumeToken(ctx context.Context, token, tokenType string) (*domain.AuthToken, error) {
	var consumed *domain.AuthToken
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var stored gormAuthToken
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			First(&stored, "token = ? AND type = ?", token, tokenType).Error; err != nil {
			return err
		}
		if !stored.ExpiresAt.After(time.Now()) {
			if err := tx.Delete(&stored).Error; err != nil {
				return err
			}
			return domain.ErrExpired
		}
		if err := tx.Delete(&stored).Error; err != nil {
			return err
		}
		consumed = toCoreAuthToken(&stored)
		return nil
	})
	if err != nil {
		if errors.Is(err, domain.ErrExpired) {
			return nil, err
		}
		return nil, storageError("consume token", err)
	}
	return consumed, nil
}

// DeleteToken implements domain.TokenStore.
func (r *Repository) DeleteToken(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Delete(&gormAuthToken{}, "token = ?", token).Error
}

// DeleteExpiredTokens implements domain.TokenStore.
func (r *Repository) DeleteExpiredTokens(ctx context.Context) error {
	return r.db.WithContext(ctx).Delete(&gormAuthToken{}, "expires_at < ?", time.Now()).Error
}

// applyFilter applies audit.Filter to a GORM DB.
func (r *Repository) applyFilter(db *gorm.DB, filter audit.Filter) *gorm.DB {
	if filter.TenantID != "" {
		db = db.Where("tenant_id = ?", filter.TenantID)
	}
	if filter.ActorID != "" {
		db = db.Where("actor_id = ?", filter.ActorID)
	}
	if filter.SubjectID != "" {
		db = db.Where("subject_id = ?", filter.SubjectID)
	}
	if len(filter.Types) > 0 {
		db = db.Where("type IN ?", filter.Types)
	}
	if len(filter.Statuses) > 0 {
		db = db.Where("status IN ?", filter.Statuses)
	}
	if len(filter.RiskLevels) > 0 {
		db = db.Where("risk IN ?", filter.RiskLevels)
	}
	if filter.ResourceType != "" {
		db = db.Where("resource_type = ?", filter.ResourceType)
	}
	if filter.ResourceID != "" {
		db = db.Where("resource_id = ?", filter.ResourceID)
	}
	if !filter.StartTime.IsZero() {
		db = db.Where("created_at >= ?", filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		db = db.Where("created_at <= ?", filter.EndTime)
	}
	if filter.IPAddress != "" {
		db = db.Where("ip_address = ?", filter.IPAddress)
	}
	if filter.SessionID != "" {
		db = db.Where("session_id = ?", filter.SessionID)
	}

	if filter.OrderBy != "" {
		db = db.Order(filter.OrderBy)
	} else {
		db = db.Order("created_at DESC")
	}

	if filter.Limit > 0 {
		db = db.Limit(filter.Limit)
	}
	if filter.Offset > 0 {
		db = db.Offset(filter.Offset)
	}

	return db
}

// Query implements audit.AuditStore.
func (r *Repository) Query(ctx context.Context, filter audit.Filter) ([]audit.AuditEvent, error) {
	var gormEvents []gormAuditEvent
	db := r.applyFilter(r.db.WithContext(ctx), filter)

	if err := db.Find(&gormEvents).Error; err != nil {
		return nil, fmt.Errorf("gormstore: failed to query audit events: %w", err)
	}

	events := make([]audit.AuditEvent, len(gormEvents))
	for i, ge := range gormEvents {
		events[i] = *toCoreAuditEvent(&ge)
	}
	return events, nil
}

// Count implements audit.AuditStore.
func (r *Repository) Count(ctx context.Context, filter audit.Filter) (int64, error) {
	var count int64
	db := r.applyFilter(r.db.WithContext(ctx), filter)
	// Clear order, limit, offset for count
	db = db.Order(nil).Limit(-1).Offset(-1)

	if err := db.Model(&gormAuditEvent{}).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("gormstore: failed to count audit events: %w", err)
	}
	return count, nil
}

// Export implements audit.AuditStore.
func (r *Repository) Export(ctx context.Context, filter audit.Filter, format audit.ExportFormat) (io.Reader, error) {
	events, err := r.Query(ctx, filter)
	if err != nil {
		return nil, err
	}

	return audit.ExportEvents(events, format)
}

// Purge implements audit.AuditStore.
func (r *Repository) Purge(ctx context.Context, olderThan time.Time) (int64, error) {
	res := r.db.WithContext(ctx).Delete(&gormAuditEvent{}, "created_at < ?", olderThan)
	return res.RowsAffected, res.Error
}

// Compile-time interface checks
var (
	_ domain.IdentityStorage = (*Repository)(nil)
	_ domain.SessionStorage  = (*Repository)(nil)
	_ domain.TokenStore      = (*Repository)(nil)
	_ audit.AuditStore       = (*Repository)(nil)
)

// AutoMigrate creates or updates tables from the Go models.
//
// Deprecated: use [Repository.AutoMigrateDev] for development, or apply the
// versioned SQL from [Migrations] in production. The name did not say which
// of those it was for.
func (r *Repository) AutoMigrate(models ...any) error {
	return r.AutoMigrateDev(models...)
}
