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
	"encoding/json"
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
		&gormGroup{},
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
		return nil, fmt.Errorf("kgorm: failed to query audit events: %w", err)
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
		return 0, fmt.Errorf("kgorm: failed to count audit events: %w", err)
	}
	return count, nil
}

// Export implements audit.AuditStore.
func (r *Repository) Export(ctx context.Context, filter audit.Filter, format audit.ExportFormat) (io.Reader, error) {
	events, err := r.Query(ctx, filter)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		if format == audit.ExportJSON {
			if err := json.NewEncoder(pw).Encode(events); err != nil {
				pw.CloseWithError(err)
			}
		} else {
			// CSV or other formats could be implemented here
			pw.CloseWithError(errors.New("kgorm: unsupported export format"))
		}
	}()

	return pr, nil
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
